import Link from 'next/link';
import type { readRegistryItem } from './client';
import { date, requestTypes, statuses } from './format';

export default function RequestTable({ items }: { items: ReturnType<typeof readRegistryItem>[] }) {
  return <div className="registry-table"><table>
    <thead><tr><th scope="col">Номер</th><th scope="col">Создана (UTC)</th><th scope="col">Тип</th><th scope="col">Статус</th></tr></thead>
    <tbody>{items.map(row => <tr key={row.id}><td><Link href={`/crm/requests/${row.id}`}>{row.publicNumber}</Link></td>
      <td><time dateTime={row.createdAt}>{date.format(new Date(row.createdAt))}</time></td>
      <td>{requestTypes[row.type]}</td><td>{statuses[row.status]}</td></tr>)}</tbody>
  </table></div>;
}
