// Clipboard with a graceful fallback: if the async Clipboard API is unavailable or
// denied, select the text in the given element so the user can copy it manually.

export type CopyResult = "copied" | "selected" | "failed";

export async function copyText(text: string, fallbackEl: HTMLElement | null): Promise<CopyResult> {
  try {
    // navigator.clipboard is undefined outside secure contexts, despite the DOM typings.
    const clip = (navigator as Partial<Navigator>).clipboard;
    if (clip !== undefined) {
      await clip.writeText(text);
      return "copied";
    }
  } catch {
    // fall through to manual selection
  }
  return selectElementText(fallbackEl) ? "selected" : "failed";
}

export function selectElementText(el: HTMLElement | null): boolean {
  if (el === null) return false;
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
    el.focus();
    el.select();
    return true;
  }
  const sel = window.getSelection();
  if (sel === null) return false;
  const range = document.createRange();
  range.selectNodeContents(el);
  sel.removeAllRanges();
  sel.addRange(range);
  return true;
}
