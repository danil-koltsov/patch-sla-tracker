import { WINDOW_START } from "../lib/methodology.ts";

export default function NotFound() {
  return (
    <>
      <h1>Not found</h1>
      <p>
        There is no page at this address. This site covers only CVEs that an Apple iOS, iPadOS or macOS security advisory lists and that were
        first fixed on or after {WINDOW_START}. Pages live at addresses like <code>/cve/CVE-2025-24085</code>.
      </p>
      <p>
        <a href="/apple">All Apple numbers</a> · <a href="/methodology">Methodology</a>
      </p>
    </>
  );
}
