export const MAX_SCENE_FPS = 60;
export const LOW_FPS_THRESHOLD = 40;
export const LOW_FPS_DURATION_MS = 1_500;

export function isSceneFrameDue(now: number, lastFrame: number): boolean {
  return now - lastFrame >= 1_000 / MAX_SCENE_FPS;
}

export function shouldReduceSceneQuality(fps: number, lowFpsSince: number, now: number): boolean {
  return fps < LOW_FPS_THRESHOLD && now - lowFpsSince >= LOW_FPS_DURATION_MS;
}
