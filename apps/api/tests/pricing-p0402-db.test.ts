import { randomUUID } from 'node:crypto';
import { setTimeout as pause } from 'node:timers/promises';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { archiveItem, createDirectory, createItem, publishDirectory, publishFixedPrice, publishItem, replaceFixedPrice } from '../src/catalog/index.js';
import type { CatalogClient } from '../src/catalog/index.js';
import { sealPricing, verifyPricingSnapshot } from '../src/pricing/codec/index.js';
import { calculatePricing } from '../src/pricing/engine/index.js';
import {
  archiveEstimate, archiveRule, closeEstimate, closePolicy, closeRule, createEstimate, createRule, publishEstimate, publishPolicy, publishRule,
  readEffectiveEstimates, readPricingInput, replaceEstimate, replacePolicy, replaceRule,
} from '../src/pricing/repository/index.js';
import type { PolicyBody, ReadPricingInput } from '../src/pricing/repository/index.js';
import { addSyntheticCityVersion, configurationIntegration, createConfigurationFixture, createSyntheticCity } from './configuration-fixture.js';
import type { ConfigurationFixture, SyntheticCity } from './configuration-fixture.js';

const TEST_TIMEOUT = 24_000;
const tariffAt = '2026-11-01T05:30:00.000Z';
const sourceRef = 'review://synthetic/pricing';
const code = (prefix: string) => `${prefix}-${randomUUID()}`;
function first<T>(rows: readonly T[]): T {
  const row = rows[0];
  if (row === undefined) {throw new Error('Missing isolated pricing test row');}
  return row;
}

configurationIntegration('P04-02 real pricing ports and single-snapshot calculation', () => {
  let f: ConfigurationFixture;
  let closeFixture: (() => Promise<void>) | undefined;
  beforeAll(async () => {
    f = await createConfigurationFixture();
    closeFixture = () => f.close();
  }, 60_000);
  afterAll(async () => { await closeFixture?.(); }, 30_000);
  function tx<T>(run: (c: CatalogClient, actor: string) => Promise<T>): Promise<T> {
    return f.inTransaction(c => run(c, f.reviewer));
  }
  async function observed(check: () => Promise<boolean>, label: string, timeout = 6500): Promise<void> {
    const deadline = performance.now() + timeout;
    do {
      if (await check()) {return;}
      await pause(12);
    } while (performance.now() < deadline);
    throw new Error(`Isolated pricing checkpoint not reached: ${label}`);
  }
  async function dbAt(ms = 0): Promise<string> {
    const {rows} = await f.runtime.query<{value:Date}>(`SELECT date_trunc('milliseconds',clock_timestamp()) + $1::integer * interval '1 millisecond' AS value`, [ms]);
    return first(rows).value.toISOString();
  }
  async function waitAt(at: string): Promise<void> {
    await observed(async () => (await dbAt()) >= at, 'effective time');
  }
  async function catalog(c: CatalogClient, actor: string) {
    const draft = await createDirectory(c,actor,{kind:'CATEGORY',code:code('pricing-cat')});
    const category = await publishDirectory(c,actor,{id:draft.id,expectedVersion:draft.version,title:'Synthetic appliance'});
    const sku = await createItem(c,actor,{kind:'WORK',categoryId:category.id,code:code('pricing-work'),unit:'piece'});
    const item = await publishItem(c,actor,{id:sku.id,kind:'WORK',expectedVersion:sku.version,title:'Reviewed labor',durationMinutes:30,
      technicianVisible:true,publicVisible:false});
    return {category,item};
  }
  function request(city:SyntheticCity,itemId:string, quantity='2'):ReadPricingInput {
    return { calculationId:randomUUID(), cityId:city.id,cityVersionId:city.versionId,tariffAt,express:true,
      selections:[{lineId:randomUUID(),itemId,quantity,unit:'piece'}],adjustments:[],evidence:[],visibility:'TECHNICIAN' };
  }
  function policy(overrides:Partial<PolicyBody>={}):PolicyBody {
    return {currency:'RUB',taxDisplay:'Synthetic tax display',roundingMode:'HALF_UP',units:{piece:2},maxManualDeltaMinor:'100',
      priorities:[],compatibilities:[],...overrides};
  }
  function fixed(cityId:string,itemId:string,validFrom:string,amountMinor='3100') {
    return {cityId,itemId,validFrom,expectedVersion:0,sourceRef,currency:'RUB',amountMinor};
  }
  async function pid(c:PoolClient):Promise<number> {
    return first((await c.query<{pid:number}>('SELECT pg_catalog.pg_backend_pid() AS pid')).rows).pid;
  }
  async function waitReader(holder:number,waiter:number) {
    await observed(async () => first((await f.runtime.query<{blocked:boolean}>(`SELECT EXISTS(SELECT FROM pg_locks
      WHERE pid=$2 AND NOT granted AND locktype='advisory' AND classid=77304 AND objid=1 AND objsubid=2
        AND mode='ShareLock' AND $1=ANY(pg_blocking_pids($2))) AS blocked`,[holder,waiter])).rows).blocked, 'shared fence',3200);
  }
  async function clients<T>(body:(a:PoolClient,b:PoolClient)=>Promise<T>):Promise<T> {
    const a=await f.runtime.connect();
    try {
      const b=await f.runtime.connect();
      try {
        for (const c of [a,b]) {await c.query('BEGIN'); await c.query("SET LOCAL statement_timeout='8s'");}
        return await body(a,b);
      } finally {
        try {await a.query('ROLLBACK');}
        finally {try {await b.query('ROLLBACK');} finally {b.release();}}
      }
    } finally {a.release();}
  }

  it('resolves both DST folds and immutable provenance across repricing, rename, timezone change and archive', async () => {
    const city=await createSyntheticCity(f,{timezone:'America/New_York'});
    const {category,item}=await tx(catalog);
    const at=await dbAt(1500);
    const setup=await tx(async(c,a)=>{
      const evening=await createRule(c,a,{code:code('evening'),kind:'EVENING'});
      const night=await createRule(c,a,{code:code('night'),kind:'NIGHT'});
      const express=await createRule(c,a,{code:code('express'),kind:'EXPRESS'});
      const price=await publishFixedPrice(c,a,fixed(city.id,item.id,at));
      const base={cityId:city.id,validFrom:at,expectedVersion:0,sourceRef,base:'WORKS',currency:'RUB',categoryIds:[category.id]} as const;
      await publishRule(c,a,{...base,ruleId:evening.id,kind:'EVENING',method:'FIXED',title:'Synthetic evening',fixedMinor:'1000',
        startMinute:0,endMinute:180,wrapsMidnight:false});
      const n=await publishRule(c,a,{...base,ruleId:night.id,kind:'NIGHT',method:'RATE',title:'Synthetic night',rateBps:2500,
        startMinute:1320,endMinute:240,wrapsMidnight:true});
      await publishRule(c,a,{...base,ruleId:express.id,kind:'EXPRESS',method:'FIXED',title:'Synthetic express',fixedMinor:'200'});
      const p=await publishPolicy(c,a,{cityId:city.id,expectedVersion:0,validFrom:at,sourceRef,...policy({
        priorities:[{ruleId:express.id,priority:1},{ruleId:evening.id,priority:4},{ruleId:night.id,priority:5}],
        compatibilities:[{leftRuleId:night.id,rightRuleId:express.id}],
      })});
      return {price,n,p};
    });
    await waitAt(at);
    const req=request(city,item.id);
    const actual=await tx(c=>readPricingInput(c,req));
    expect(actual.context).toMatchObject({timezone:'America/New_York',localAt:'2026-11-01T01:30:00.000',utcOffsetSeconds:-14400});
    const fold=await tx(c=>readPricingInput(c,{...req,tariffAt:'2026-11-01T06:30:00.000Z'}));
    expect(fold.context).toMatchObject({localAt:actual.context.localAt,utcOffsetSeconds:-18000});
    expect(actual.policy.id).toBe(setup.p.revisionId);
    expect(actual.rules).toContainEqual(expect.objectContaining({id:setup.n.revisionId,categoryIds:[category.id]}));
    const sealed=sealPricing(actual);
    expect(verifyPricingSnapshot(sealed.bytes,sealed.sha256)).toMatchObject({totalMinor:'7950',breakdown:{works:'6200',timeSurcharge:'1550',expressSurcharge:'200'}});
    const nextCityVersion=await addSyntheticCityVersion(f,city,{timezone:'UTC',version:2});
    // Guarded GEO/CFG basis write (migration 022): the unified writer fence must be
    // held before the statement, on the same pinned migrator client.
    {
      const client=await f.migrator.connect();
      try {
        await client.query('BEGIN');
        await client.query('SELECT pg_advisory_xact_lock(734305,1)');
        await client.query('UPDATE foundation.service_cities SET current_version_id=$2 WHERE id=$1',[city.id,nextCityVersion]);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK').catch(()=>undefined);
        throw error;
      } finally { client.release(); }
    }
    const replacementAt=await dbAt(1300);
    const changed=await tx(async(c,a)=>{
      const renamed=await publishItem(c,a,{id:item.id,expectedVersion:item.version,kind:'WORK',title:'Renamed labor',durationMinutes:35,
        technicianVisible:true,publicVisible:false});
      const priced=await replaceFixedPrice(c,a,{cityId:city.id,itemId:item.id,priceVersionId:setup.price.revisionId,expectedVersion:setup.price.version,
        at:replacementAt,sourceRef,currency:'RUB',amountMinor:'4500'});
      return {renamed,priced};
    });
    expect(await tx(c=>readPricingInput(c,{...req,cityVersionId:nextCityVersion}))).toMatchObject({
      items:[{title:'Renamed labor',itemVersionId:changed.renamed.revisionId,price:{id:setup.price.revisionId,itemVersionId:item.revisionId}}],
    });
    await expect(tx(c=>readPricingInput(c,req))).rejects.toBeDefined();
    await waitAt(replacementAt);
    const current=await tx(c=>readPricingInput(c,{...req,cityVersionId:nextCityVersion}));
    expect(current).toMatchObject({items:[{price:{id:changed.priced.revisionId,amountMinor:'4500'}}],context:{timezone:'UTC',utcOffsetSeconds:0}});
    await tx((c,a)=>archiveItem(c,a,{id:item.id,expectedVersion:changed.renamed.version}));
    await expect(tx(c=>readPricingInput(c,{...req,cityVersionId:nextCityVersion}))).rejects.toBeDefined();
    expect(sealPricing(verifyPricingSnapshot(sealed.bytes,sealed.sha256).input)).toEqual(sealed);
  },TEST_TIMEOUT);

  it('does not use another city or a reviewed range to fill a missing fixed price or policy', async () => {
    const [a,b]=[await createSyntheticCity(f),await createSyntheticCity(f)];
    const {category,item}=await tx(catalog);
    const at=await dbAt(1300);
    const result=await tx(async(c,actor)=>{
      const range=await createEstimate(c,actor,{cityId:b.id,categoryId:category.id,code:code('range')});
      const reviewed=await publishEstimate(c,actor,{cityId:b.id,estimateId:range.id,expectedVersion:range.version,sourceRef,validFrom:at,
        currency:'RUB',title:'Reviewed range',minMinor:'0',maxMinor:'30000',disclaimer:'Not an exact price'});
      const aPrice=await publishFixedPrice(c,actor,fixed(a.id,item.id,at));
      await publishPolicy(c,actor,{cityId:b.id,expectedVersion:0,validFrom:at,sourceRef,...policy()});
      return {range,reviewed,aPrice};
    });
    await waitAt(at);
    const ranges={cityId:b.id,cityVersionId:b.versionId,categoryId:category.id};
    expect(await tx(c=>readEffectiveEstimates(c,ranges))).toMatchObject([{id:result.reviewed.revisionId,minMinor:'0',maxMinor:'30000'}]);
    expect(await tx(c=>readEffectiveEstimates(c,{...ranges,cityId:a.id,cityVersionId:a.versionId}))).toEqual([]);
    await expect(tx(c=>readPricingInput(c,request(a,item.id)))).rejects.toMatchObject({code:'PRICING_NOT_CONFIGURED'});
    await expect(tx(c=>readPricingInput(c,request(b,item.id)))).rejects.toMatchObject({code:'PRICE_NOT_CONFIGURED'});
    await expect(tx((c,actor)=>archiveEstimate(c,actor,{cityId:a.id,estimateId:result.range.id,expectedVersion:result.reviewed.version})))
      .rejects.toMatchObject({code:'NOT_FOUND'});
    await tx((c,actor)=>archiveEstimate(c,actor,{cityId:b.id,estimateId:result.range.id,expectedVersion:result.reviewed.version}));
    expect(await tx(c=>readEffectiveEstimates(c,ranges))).toEqual([]);
  },TEST_TIMEOUT);

  it('waits for the catalog fence and switches policy, rate and fixed sources together at the same T', async () => {
    const city=await createSyntheticCity(f,{timezone:'UTC'});
    const {item}=await tx(catalog);
    const from=await dbAt(1100);
    const initial=await tx(async(c,a)=>{
      const rule=await createRule(c,a,{code:code('express'),kind:'EXPRESS'});
      const rateBody={cityId:city.id,ruleId:rule.id,kind:'EXPRESS',method:'RATE',title:'City express',base:'WORKS',currency:'RUB',
        rateBps:1000,categoryIds:[],sourceRef} as const;
      return {rule,rateBody,rate:await publishRule(c,a,{...rateBody,expectedVersion:0,validFrom:from}),
        fixed:await publishFixedPrice(c,a,fixed(city.id,item.id,from,'1000')),
        policy:await publishPolicy(c,a,{cityId:city.id,expectedVersion:0,validFrom:from,sourceRef,...policy({priorities:[{ruleId:rule.id,priority:1}]})})};
    });
    await waitAt(from);
    const req=request(city,item.id,'1');
    await clients(async(w,r)=>{
      const writer=await pid(w),reader=await pid(r), at=await dbAt(3600);
      const p=await replacePolicy(w,f.reviewer,{...policy({priorities:[{ruleId:initial.rule.id,priority:2}]}),cityId:city.id,
        expectedVersion:initial.policy.version,versionId:initial.policy.revisionId,at,sourceRef});
      const rate=await replaceRule(w,f.reviewer,{...initial.rateBody,expectedVersion:initial.rate.version,
        versionId:initial.rate.revisionId,at,rateBps:2000});
      const priced=await replaceFixedPrice(w,f.reviewer,{cityId:city.id,itemId:item.id,priceVersionId:initial.fixed.revisionId,
        expectedVersion:initial.fixed.version,at,currency:'RUB',amountMinor:'2000',sourceRef});
      const pending=readPricingInput(r,req).then(value=>({value}), (error:unknown)=>({error}));
      await waitReader(writer,reader);
      const timeBeforeCommit=await dbAt();
      await w.query('COMMIT');
      const old=await pending;
      if ('error' in old) {throw old.error;}
      expect(old.value.context.pricingAt >= timeBeforeCommit && old.value.context.pricingAt < at).toBe(true);
      expect(old.value).toMatchObject({policy:{id:initial.policy.revisionId,effectiveUntil:at},
        items:[{price:{id:initial.fixed.revisionId,effectiveUntil:at}}],rules:[{id:initial.rate.revisionId,effectiveUntil:at}]});
      expect(calculatePricing(old.value).totalMinor).toBe('1100');
      await r.query('COMMIT'); await waitAt(at);
      const changed=await tx(c=>readPricingInput(c,req));
      expect(changed).toMatchObject({policy:{id:p.revisionId},items:[{price:{id:priced.revisionId}}],rules:[{id:rate.revisionId}]});
      expect(calculatePricing(changed).totalMinor).toBe('2400');
    });
  },TEST_TIMEOUT);

  it('bounds publication, rejects overlapping prices and foreign version targets, and closes each stream only once', async () => {
    const [a,b]=[await createSyntheticCity(f),await createSyntheticCity(f)];
    const {category}=await tx(catalog);
    const rule=await tx((c,actor)=>createRule(c,actor,{code:code('time-rate'),kind:'NIGHT'}));
    const at=await dbAt(1400);
    const ruleBody={ruleId:rule.id,kind:'NIGHT',method:'RATE',title:'Synthetic rate',base:'ORDER_BASE',currency:'RUB',
      rateBps:10000,startMinute:1260,endMinute:240,wrapsMidnight:true,categoryIds:[],sourceRef} as const;
    await expect(tx((c,actor)=>publishRule(c,actor,{...ruleBody,cityId:a.id,expectedVersion:0,validFrom:at,rateBps:10001})))
      .rejects.toMatchObject({code:'INVALID_INPUT'});
    const published=await tx(async(c,actor)=>{
      const ra=await publishRule(c,actor,{...ruleBody,cityId:a.id,expectedVersion:0,validFrom:at});
      const rb=await publishRule(c,actor,{...ruleBody,cityId:b.id,expectedVersion:0,validFrom:at});
      const p=await publishPolicy(c,actor,{cityId:a.id,expectedVersion:0,validFrom:at,sourceRef,...policy()});
      const range=await createEstimate(c,actor,{cityId:a.id,categoryId:category.id,code:code('range')});
      const body={cityId:a.id,estimateId:range.id,expectedVersion:range.version,sourceRef,currency:'RUB',
        title:'Synthetic range',minMinor:'20',maxMinor:'40',disclaimer:'Not an invoice'};
      const e=await publishEstimate(c,actor,{...body,validFrom:at});
      return {ra,rb,p,e,body};
    });
    const overlap={...ruleBody,cityId:a.id,expectedVersion:published.ra.version,validFrom:await dbAt(4500)};
    await expect(tx((c,a)=>publishRule(c,a,overlap))).rejects.toMatchObject({code:'CONFLICT',field:'period'});
    await waitAt(at);
    const cut=await dbAt(1500);
    await expect(tx((c,actor)=>closeRule(c,actor,{cityId:a.id,ruleId:rule.id,expectedVersion:published.ra.version,
      versionId:published.rb.revisionId,at:cut}))).rejects.toMatchObject({code:'NOT_FOUND'});
    await tx(async(c,actor)=>{
      await closeRule(c,actor,{cityId:a.id,ruleId:rule.id,expectedVersion:published.ra.version,versionId:published.ra.revisionId,at:cut});
      await closePolicy(c,actor,{cityId:a.id,expectedVersion:published.p.version,versionId:published.p.revisionId,at:cut});
      await replaceEstimate(c,actor,{...published.body,expectedVersion:published.e.version,versionId:published.e.revisionId,at:cut,minMinor:'30'});
    });
    await expect(tx((c,actor)=>closePolicy(c,actor,{cityId:a.id,expectedVersion:published.p.version+1,versionId:published.p.revisionId,at:cut})))
      .rejects.toMatchObject({code:'CONFLICT',field:'at'});
    await waitAt(cut);
    const ranges={cityId:a.id,cityVersionId:a.versionId,categoryId:category.id};
    const newRange=first(await tx(c=>readEffectiveEstimates(c,ranges)));
    expect(newRange).toMatchObject({minMinor:'30',validFrom:cut});
    const finish=await dbAt(900);
    await tx((c,actor)=>closeEstimate(c,actor,{cityId:a.id,estimateId:published.body.estimateId,expectedVersion:published.e.version+1,
      versionId:newRange.id,at:finish}));
    await waitAt(finish);
    expect(await tx(c=>readEffectiveEstimates(c,ranges))).toEqual([]);
    await tx((c,actor)=>archiveRule(c,actor,{ruleId:rule.id,expectedVersion:rule.version}));
    await expect(tx((c,actor)=>publishRule(c,actor,{...ruleBody,cityId:a.id,expectedVersion:published.ra.version+1,validFrom:overlap.validFrom})))
      .rejects.toMatchObject({code:'ARCHIVED'});
  },TEST_TIMEOUT);

  it('does not persist projection, CAS, children or audit when outbox write fails after replacing a policy', async () => {
    const city=await createSyntheticCity(f);
    const rule=await tx((c,a)=>createRule(c,a,{code:code('failure-rule'),kind:'EXPRESS'}));
    const at=await dbAt(1000);
    const initial=await tx((c,a)=>publishPolicy(c,a,{cityId:city.id,expectedVersion:0,validFrom:at,sourceRef,...policy()}));
    await waitAt(at);
    await f.migrator.query(`CREATE FUNCTION foundation.p0402_failout() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
      BEGIN IF NEW.event_type='pricing.policy.replace' THEN RAISE EXCEPTION 'synthetic outbox failure' USING ERRCODE='23514'; END IF;
      RETURN NEW; END $$;
      CREATE TRIGGER p0402_failout BEFORE INSERT ON foundation.outbox_events FOR EACH ROW EXECUTE FUNCTION foundation.p0402_failout()`);
    try {
      const end=await dbAt(2200);
      await tx(async(c,a)=>{
        await expect(replacePolicy(c,a,{cityId:city.id,expectedVersion:initial.version,versionId:initial.revisionId,at:end,sourceRef,
          ...policy({priorities:[{ruleId:rule.id,priority:42}]})})).rejects.toMatchObject({name:'CatalogInternalError'});
      });
    } finally {
      await f.migrator.query('DROP TRIGGER p0402_failout ON foundation.outbox_events; DROP FUNCTION foundation.p0402_failout()');
    }
    expect((await f.runtime.query(`SELECT s.row_version, p.closed_effective_until,
      (SELECT count(*)::int FROM foundation.pricing_policy_versions v WHERE v.series_id=s.id) AS versions,
      (SELECT count(*)::int FROM foundation.price_rule_priorities d JOIN foundation.pricing_policy_versions v ON v.id=d.policy_version_id WHERE v.series_id=s.id) AS rules,
      (SELECT count(*)::int FROM foundation.audit_logs WHERE operation='pricing.policy.replace' AND details->>'id'=s.id::text) AS audit,
      (SELECT count(*)::int FROM foundation.outbox_events WHERE event_type='pricing.policy.replace' AND payload->>'id'=s.id::text) AS outbox
      FROM foundation.pricing_policy_series s JOIN foundation.pricing_policy_periods p ON p.series_id=s.id WHERE s.id=$1`,[initial.id])).rows)
      .toEqual([{row_version:1,closed_effective_until:null,versions:1,rules:0,audit:0,outbox:0}]);
  },TEST_TIMEOUT);
});
