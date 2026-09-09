// All upsell / sign-up CTAs route anonymous local-viewer users to the public
// cloud sign-up. Open in a new tab so the local results stay put.
export const SIGNUP_URL = "https://app.strix.ai/api/auth/signup";
export const DEMO_URL = "https://strix.ai/demo";
export const PRICING_URL = "https://strix.ai/pricing";

// Attribution params appended to every outbound CTA link so the destination
// analytics can see the local viewer drove the click, with utm_content carrying
// the CTA slug so we know which one.
const CTA_PARAMS =
  "ref=oss_viewer&utm_source=oss_viewer&utm_medium=local_viewer&utm_campaign=oss_viewer";

export function ctaUrl(base: string, slug: string): string {
  const sep = base.includes("?") ? "&" : "?";
  return `${base}${sep}${CTA_PARAMS}&utm_content=${encodeURIComponent(slug)}`;
}

// Kept as no-ops so call sites stay simple; Strix no longer emits viewer beacons.
export function track(_event: string, _props: Record<string, string | undefined> = {}): void {}

export function trackCta(_cta: string, _surface?: string): void {}
