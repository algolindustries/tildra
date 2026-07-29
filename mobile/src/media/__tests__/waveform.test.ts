import { describe, expect, it } from 'vitest';

import {
  WAVEFORM_BUCKETS,
  WAVEFORM_MAX,
  barHeights,
  buildWaveform,
  formatDuration,
  meteringToAmplitude,
  playbackProgress,
} from '../waveform';

describe('waveform', () => {
  it('always produces a fixed width', () => {
    for (const count of [0, 1, 7, 48, 1000]) {
      const samples = Array.from({ length: count }, (_, i) => i % 10);
      expect(buildWaveform(samples)).toHaveLength(WAVEFORM_BUCKETS);
    }
  });

  it('normalises against the loudest bucket', () => {
    const samples = Array.from({ length: 480 }, (_, i) => (i < 240 ? 0.1 : 0.5));
    const waveform = buildWaveform(samples);

    expect(Math.max(...waveform)).toBe(WAVEFORM_MAX);
    // The quiet half stays visibly quieter rather than being amplified flat.
    expect(waveform[0]).toBeLessThan(WAVEFORM_MAX / 2);
  });

  it('keeps silence flat instead of amplifying noise', () => {
    expect(Array.from(buildWaveform(new Array(200).fill(0)))).toEqual(
      new Array(WAVEFORM_BUCKETS).fill(0),
    );
  });

  it('takes the peak of each window, not the mean', () => {
    // One loud sample in an otherwise quiet window must still show up: that is
    // where a word is, and a mean would erase it.
    const samples = new Array(480).fill(0.01);
    samples[5] = 1;
    const waveform = buildWaveform(samples);

    expect(waveform[0]).toBe(WAVEFORM_MAX);
    expect(waveform[10]).toBeLessThan(WAVEFORM_MAX);
  });

  it('handles fewer samples than buckets without gaps', () => {
    const waveform = buildWaveform([1, 0.5, 1]);
    expect(waveform).toHaveLength(WAVEFORM_BUCKETS);
    expect(Math.max(...waveform)).toBe(WAVEFORM_MAX);
  });

  it('treats negative samples by magnitude', () => {
    const positive = buildWaveform([0, 0.8, 0]);
    const negative = buildWaveform([0, -0.8, 0]);
    expect(Array.from(positive)).toEqual(Array.from(negative));
  });
});

describe('metering conversion', () => {
  it('maps the decibel floor to silence and 0 dB to full scale', () => {
    expect(meteringToAmplitude(-160)).toBe(0);
    expect(meteringToAmplitude(-60)).toBe(0);
    expect(meteringToAmplitude(0)).toBe(1);
  });

  it('is monotonic across the speech range', () => {
    const values = [-50, -40, -30, -20, -10, -5].map(meteringToAmplitude);
    for (let i = 1; i < values.length; i++) {
      expect(values[i]).toBeGreaterThan(values[i - 1]);
    }
  });

  it('spreads the speech range instead of clustering it near the top', () => {
    // Decibels plotted directly make everything look equally loud. Linear
    // amplitude is what makes the picture readable.
    const quiet = meteringToAmplitude(-40);
    const loud = meteringToAmplitude(-10);
    expect(loud / Math.max(quiet, 1e-9)).toBeGreaterThan(10);
  });

  it('reads a nonsensical meter value as silence, not as full scale', () => {
    // We do not know what the level was. Drawing a full-height bar would
    // invent loudness that may not have happened; a flat bar understates and
    // is the safer of the two.
    expect(meteringToAmplitude(NaN)).toBe(0);
    expect(meteringToAmplitude(Infinity)).toBe(0);
    expect(meteringToAmplitude(-Infinity)).toBe(0);
  });
});

describe('duration formatting', () => {
  it('formats as mm:ss', () => {
    expect(formatDuration(0)).toBe('0:00');
    expect(formatDuration(1_000)).toBe('0:01');
    expect(formatDuration(61_000)).toBe('1:01');
    expect(formatDuration(600_000)).toBe('10:00');
  });

  it('rounds to the nearest second and never shows a negative', () => {
    expect(formatDuration(1_600)).toBe('0:02');
    expect(formatDuration(-500)).toBe('0:00');
  });
});

describe('bar rendering', () => {
  it('gives silence a visible floor rather than a gap', () => {
    // A waveform with holes in it reads as a corrupted file.
    const heights = barHeights(new Uint8Array([0, 15, 0]));
    expect(heights[0]).toBeGreaterThan(0);
    expect(heights[1]).toBeCloseTo(1);
  });

  it('stays within 0 and 1', () => {
    const heights = barHeights(new Uint8Array([0, 3, 7, 11, 15]));
    heights.forEach((h) => {
      expect(h).toBeGreaterThan(0);
      expect(h).toBeLessThanOrEqual(1);
    });
  });
});

describe('playback progress', () => {
  it('is a fraction bounded to the clip', () => {
    expect(playbackProgress(0, 1000)).toBe(0);
    expect(playbackProgress(500, 1000)).toBe(0.5);
    expect(playbackProgress(2000, 1000)).toBe(1);
    expect(playbackProgress(-10, 1000)).toBe(0);
  });

  it('does not divide by zero on an unknown duration', () => {
    expect(playbackProgress(100, 0)).toBe(0);
  });
});
