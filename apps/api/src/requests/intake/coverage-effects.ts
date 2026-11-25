import type { GuardedPool } from '../../infrastructure/admission/pool-guard.js';
import { deny } from './errors.js';
import { recordCoverageAssessment, requestEffectsAuditStore, reproofCoverageBasis } from './coverage.js';
import type { CoverageReviewEvidencePort } from './coverage.js';
import type { CoverageEffect } from './service.js';
import type { Snapshots } from './store.js';

export function coverageEffects(config: Snapshots, auditPool: GuardedPool, evidence: CoverageReviewEvidencePort, cap: number): CoverageEffect {
  const audit = requestEffectsAuditStore(auditPool);
  return {
    async assess({ client, actor, request, body, eventId, recheck }) {
      if (!request.current_address_revision_id) { return deny('COVERAGE_ASSESSMENT_STALE'); }
      const effect = await recordCoverageAssessment({ client,ring:config.ring,environment:config.environment,keySlots:config.keySlots,
        actor:{staffId:actor.staffId},request:{ requestId:request.id,cityId:request.city_id,
          addressRevisionId:request.current_address_revision_id,expectedVersion:request.row_version },
        evidenceHandle:body.evidenceId,selection:body,cap,evidence,audit,recheck });
      await client.query(`INSERT INTO foundation.request_coverage_assessments
        (id,request_id,address_revision_id,city_id,city_version_id,area_id,area_version_id,basis_digest,outcome,reason,staff_id,
          attempt_correlation_id,event_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [effect.assessmentId,effect.requestId,effect.addressRevisionId,effect.cityId,effect.cityVersionId,effect.areaId,
        effect.areaVersionId,effect.basisDigest,effect.outcome,effect.reason,effect.staffId,effect.attemptCorrelationId,eventId]);
      return { id:effect.assessmentId, expiresAt:effect.evidenceExpiresAt };
    },
    async eligible(client, request) {
      if (!request.current_assessment_id || !request.current_address_revision_id) { return false; }
      const { rows:[assessment] } = await client.query<{ basis_digest: string; outcome: string; area_id: string; area_version_id: string }>(`
        SELECT basis_digest,outcome,area_id,area_version_id FROM foundation.request_coverage_assessments
        WHERE id=$1 AND request_id=$2 AND address_revision_id=$3 AND city_id=$4`,
      [request.current_assessment_id,request.id,request.current_address_revision_id,request.city_id]);
      if (!assessment || (assessment.outcome !== 'IN_ZONE' && assessment.outcome !== 'EXCEPTION')) { return false; }
      const basis = await reproofCoverageBasis(client,request.city_id,request.current_address_revision_id,assessment.basis_digest,cap);
      return basis.zones.some(zone => zone.areaId === assessment.area_id && zone.areaVersionId === assessment.area_version_id);
    },
  };
}
