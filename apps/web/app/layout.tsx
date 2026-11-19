import type { Metadata } from 'next';
import type { ReactNode } from 'react';

export const metadata: Metadata = {
  title: 'Техническая проверка web',
  robots: { index: false, follow: false, nocache: true },
};

export default function RootLayout({ children }: { readonly children: ReactNode }) {
  return (
    <html lang="ru">
      <body>{children}</body>
    </html>
  );
}
