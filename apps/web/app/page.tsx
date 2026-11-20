import Link from 'next/link';

export default function TechnicalPage() {
  return (
    <main>
      <h1>Техническая проверка web</h1>
      <p>Сборочный стенд P01-01.3. Для работы с сотрудниками требуется вход в закрытую CRM.</p>
      <Link href="/crm/access" prefetch={false}>Сотрудники и доступ — вход в CRM</Link>
      <output data-testid="web-foundation">web-foundation-ok</output>
    </main>
  );
}
