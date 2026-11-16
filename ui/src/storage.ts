// Keeping captures between visits, if you ask for it.
//
// The app's standing promise is that closing the tab removes everything, and
// that is worth more than the convenience of coming back to yesterday's
// analysis. So this is off by default and never turns itself on: the setting
// is a decision somebody makes about their own network's traffic, not a
// default somebody discovers afterwards.
//
// What is stored is the *report* - findings, counters, conversations,
// addressing - never the capture file. A restored capture can show everything
// the dashboard shows; its packets, its assistant and its export need the
// file, which the browser cannot hold on to across a reload. The explorer
// already says so when a capture has no file behind it.

import type { Capture } from './report';

const RETAIN = 'athernet.retain.v1';
const CAPTURES = 'athernet.captures.v1';

export function retentionIsOn(): boolean {
  try {
    return localStorage.getItem(RETAIN) === 'yes';
  } catch {
    // Private windows and blocked site data both land here. Treating that as
    // "off" is the safe reading in both directions: nothing is kept, and
    // nothing claims to have been.
    return false;
  }
}

export function setRetention(on: boolean) {
  try {
    if (on) {
      localStorage.setItem(RETAIN, 'yes');
    } else {
      localStorage.removeItem(RETAIN);
      localStorage.removeItem(CAPTURES);
    }
  } catch {
    /* nothing to do, and the caller reads the state back */
  }
}

export function loadCaptures(): Capture[] {
  if (!retentionIsOn()) return [];
  try {
    const raw = localStorage.getItem(CAPTURES);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as Capture[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/**
 * Returns an error message when the captures could not be kept, so the app
 * can say so rather than quietly dropping them. Running out of room is the
 * usual reason: a report for a busy capture is tens of kilobytes and the
 * browser gives a page about five megabytes in total.
 */
export function saveCaptures(captures: Capture[]): string | null {
  if (!retentionIsOn()) return null;
  try {
    localStorage.setItem(CAPTURES, JSON.stringify(captures));
    return null;
  } catch {
    try {
      localStorage.removeItem(CAPTURES);
    } catch {
      /* nothing left to try */
    }
    return 'There was not enough room in this browser to keep these captures, so nothing was kept. Close some of them, or turn keeping off.';
  }
}

export function forgetEverything() {
  try {
    localStorage.removeItem(CAPTURES);
  } catch {
    /* nothing to do */
  }
}

/** Roughly how much room the kept captures are using, for the control. */
export function storedSize(): number {
  try {
    return localStorage.getItem(CAPTURES)?.length ?? 0;
  } catch {
    return 0;
  }
}
