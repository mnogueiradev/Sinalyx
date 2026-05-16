export interface CsvColumn<TItem> {
  header: string
  value: (item: TItem) => unknown
}

function csvValue(value: unknown): string {
  if (value === null || typeof value === 'undefined') {
    return ''
  }
  const text = typeof value === 'object' ? JSON.stringify(value) : String(value)
  return `"${text.replace(/"/g, '""')}"`
}

function downloadFile(filename: string, content: string, type: string): void {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

export function exportCsv<TItem>(
  filename: string,
  rows: TItem[],
  columns: CsvColumn<TItem>[],
): boolean {
  if (rows.length === 0) {
    return false
  }

  const header = columns.map((column) => csvValue(column.header)).join(',')
  const body = rows
    .map((row) => columns.map((column) => csvValue(column.value(row))).join(','))
    .join('\n')

  downloadFile(filename, `${header}\n${body}`, 'text/csv;charset=utf-8')
  return true
}

export function exportJson(filename: string, payload: unknown): boolean {
  if (
    payload === null ||
    typeof payload === 'undefined' ||
    (Array.isArray(payload) && payload.length === 0)
  ) {
    return false
  }

  downloadFile(
    filename,
    JSON.stringify(payload, null, 2),
    'application/json;charset=utf-8',
  )
  return true
}

export function exportHtml(filename: string, html: string): boolean {
  if (!html.trim()) {
    return false
  }

  downloadFile(filename, html, 'text/html;charset=utf-8')
  return true
}

export function dateStamp(date = new Date()): string {
  return date.toISOString().slice(0, 10)
}
