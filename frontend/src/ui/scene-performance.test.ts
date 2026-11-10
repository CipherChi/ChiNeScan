import { describe, expect, it } from 'vitest';
import { isSceneFrameDue, LOW_FPS_DURATION_MS, MAX_SCENE_FPS, shouldReduceSceneQuality } from './scene-performance';

describe('terminal scene performance policy', () => {
  it('caps rendering at 60 frames per second', () => {
    expect(MAX_SCENE_FPS).toBe(60);
    expect(isSceneFrameDue(1_000 + 16, 1_000)).toBe(false);
    expect(isSceneFrameDue(1_000 + 17, 1_000)).toBe(true);
  });

  it('reduces quality only after sustained low frame rate', () => {
    expect(shouldReduceSceneQuality(12, 2_000, 2_000 + LOW_FPS_DURATION_MS - 1)).toBe(false);
    expect(shouldReduceSceneQuality(12, 2_000, 2_000 + LOW_FPS_DURATION_MS)).toBe(true);
    expect(shouldReduceSceneQuality(40, 2_000, 9_000)).toBe(false);
  });
});
