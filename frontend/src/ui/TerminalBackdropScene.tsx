import { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { isSceneFrameDue, shouldReduceSceneQuality } from './scene-performance';

type Props = { mode: 'full' | 'reduced' };

/** Purely abstract wireframe decoration. It does not represent ChiNeScan state. */
export function TerminalBackdropScene({ mode }: Props) {
  const host = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const root = host.current;
    if (!root) return;
    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ alpha: true, antialias: false, powerPreference: 'low-power' });
    } catch { root.classList.add('webgl-unavailable'); return; }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.25));
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x07111b, 0);
    root.append(renderer.domElement);
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(58, window.innerWidth / window.innerHeight, 0.1, 100);
    camera.position.set(0, 0, 8);
    const cyan = new THREE.LineBasicMaterial({ color: 0x50d9bc, transparent: true, opacity: .22 });
    const dim = new THREE.LineBasicMaterial({ color: 0x49aa9b, transparent: true, opacity: .11 });
    const windows: THREE.Group[] = [];
    for (let i = 0; i < 9; i++) {
      const group = new THREE.Group();
      const depth = -i * 3.4;
      const w = 2.1 + (i % 3) * .35, h = 1.25 + (i % 2) * .3;
      const vertices = [-w,-h,0, w,-h,0, w,-h,0, w,h,0, w,h,0, -w,h,0, -w,h,0, -w,-h,0];
      for (let line = 0; line < 5; line++) {
        const y = h * .48 - line * .27;
        vertices.push(-w*.8,y,0,-w*.8+((line*17)%19+8)/19*w*1.5,y,0);
      }
      const geometry = new THREE.BufferGeometry();
      geometry.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));
      group.add(new THREE.LineSegments(geometry, i < 3 ? cyan : dim));
      group.position.set(((i % 3)-1) * 2.2, ((i % 2)*2-1)*1.65, depth);
      group.scale.setScalar(1 + i * .13);
      scene.add(group); windows.push(group);
    }
    const rainGeometry = new THREE.BoxGeometry(.018, .11, .018);
    const rainMaterial = new THREE.MeshBasicMaterial({ color: 0x36d9b7, transparent: true, opacity: .25 });
    const count = mode === 'full' ? 190 : 42;
    const rain = new THREE.InstancedMesh(rainGeometry, rainMaterial, count);
    const dummy = new THREE.Object3D();
    const drops = Array.from({ length: count }, () => ({ x: Math.random()*17-8.5, y: Math.random()*12-6, z: -Math.random()*24, speed: .012 + Math.random()*.024 }));
    drops.forEach((d,i) => { dummy.position.set(d.x,d.y,d.z); dummy.updateMatrix(); rain.setMatrixAt(i,dummy.matrix); });
    scene.add(rain);

    // Abstract shield and lock outlines do not indicate security state.
    const shield = new THREE.Group();
    shield.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,1,0),new THREE.Vector3(.8,.65,0),new THREE.Vector3(.66,-.35,0),new THREE.Vector3(0,-1,0),new THREE.Vector3(-.66,-.35,0),new THREE.Vector3(-.8,.65,0),new THREE.Vector3(0,1,0)]),dim));
    shield.position.set(-4.6,-1.4,-3); shield.scale.setScalar(.65); scene.add(shield);
    const lock = new THREE.Group();
    lock.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(-.3,0,0),new THREE.Vector3(-.3,.35,0),new THREE.Vector3(-.2,.55,0),new THREE.Vector3(0,.62,0),new THREE.Vector3(.2,.55,0),new THREE.Vector3(.3,.35,0),new THREE.Vector3(.3,0,0)]),dim));
    lock.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(-.48,0,0),new THREE.Vector3(.48,0,0),new THREE.Vector3(.48,-.65,0),new THREE.Vector3(-.48,-.65,0),new THREE.Vector3(-.48,0,0)]),dim));
    lock.position.set(-4.6,-1.4,-2.9); lock.scale.setScalar(.65); scene.add(lock);

    let frame = 0, last = performance.now(), lastFrame = 0, frames = 0;
    let lowFpsSince: number | null = null, qualityReduced = false;
    let visible = !document.hidden, pointerX = 0, pointerY = 0, disposed = false;
    const onPointer = (event: PointerEvent) => { pointerX = (event.clientX/window.innerWidth-.5)*.08; pointerY = (event.clientY/window.innerHeight-.5)*.05; };
    const onVisibility = () => { visible = !document.hidden; if (visible && mode === 'full') frame = requestAnimationFrame(render); else cancelAnimationFrame(frame); };
    const resize = () => { camera.aspect=window.innerWidth/window.innerHeight; camera.updateProjectionMatrix(); renderer.setSize(window.innerWidth,window.innerHeight); };
    function render(now: number) {
      if (disposed || !visible || mode !== 'full') return;
      frame=requestAnimationFrame(render);
      if (!isSceneFrameDue(now,lastFrame)) return;
      lastFrame=now;
      frames++;
      if (now-last >= 1000) {
        const fps = frames*1000/(now-last);
        root!.dataset.fps=String(Math.round(fps));
        if (fps < 40) {
          lowFpsSince ??= now;
          if (!qualityReduced && shouldReduceSceneQuality(fps, lowFpsSince, now)) {
            qualityReduced = true;
            rain.count = Math.min(42, count);
            renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, .65));
            resize();
            root!.dataset.quality = 'reduced';
          }
        } else lowFpsSince = null;
        frames=0;last=now;
      }
      const dt=Math.min(now-last,40);
      camera.position.x+=(pointerX-camera.position.x)*.025; camera.position.y+=(-pointerY-camera.position.y)*.025;
      windows.forEach((g)=>{g.position.z += dt*.0007; if(g.position.z>8)g.position.z=-27;});
      drops.forEach((d,i)=>{d.y-=d.speed*dt*.06;if(d.y < -6)d.y=6;dummy.position.set(d.x,d.y,d.z);dummy.updateMatrix();rain.setMatrixAt(i,dummy.matrix);}); rain.instanceMatrix.needsUpdate=true;
      renderer.render(scene,camera);
    }
    window.addEventListener('resize',resize); window.addEventListener('pointermove',onPointer,{passive:true}); document.addEventListener('visibilitychange',onVisibility);
    if(mode === 'full') frame=requestAnimationFrame(render); else renderer.render(scene,camera);
    return () => { disposed=true; cancelAnimationFrame(frame); window.removeEventListener('resize',resize); window.removeEventListener('pointermove',onPointer); document.removeEventListener('visibilitychange',onVisibility); scene.traverse((object)=>{ if(object instanceof THREE.Mesh || object instanceof THREE.Line){object.geometry.dispose(); const materials=Array.isArray(object.material)?object.material:[object.material];materials.forEach(m=>m.dispose());} }); renderer.dispose(); renderer.domElement.remove(); };
  }, [mode]);

  return <div ref={host} className="terminal-scene" aria-hidden="true"/>;
}
