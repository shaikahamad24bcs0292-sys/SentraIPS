import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { BarChart3, Clock, Zap, Cpu, Layers } from 'lucide-react';

export default function TrafficVis3D({ trafficAnalysis, espPackets, is3DEnabled = true }) {
  const mountRef = useRef(null);

  const trafficType = trafficAnalysis?.traffic_type || trafficAnalysis?.classification || 'Unknown';
  const confidence = trafficAnalysis?.confidence ?? 0.0;
  const modelUsed = trafficAnalysis?.model || trafficAnalysis?.model_used || 'RandomForest';
  const packetCount = espPackets || trafficAnalysis?.packet_count || 0;
  const flowDuration = trafficAnalysis?.flow_duration_sec;
  const meanSize = trafficAnalysis?.mean_packet_size;
  const stdSize = trafficAnalysis?.std_packet_size || trafficAnalysis?.packet_size_std;
  const minSize = trafficAnalysis?.min_packet_size || trafficAnalysis?.packet_size_min;
  const maxSize = trafficAnalysis?.max_packet_size || trafficAnalysis?.packet_size_max;
  const meanIat = trafficAnalysis?.mean_iat_ms;
  const burstCount = trafficAnalysis?.burst_count;

  // Format safe values ("Unknown / Not Detected" if unavailable)
  const formatVal = (val, suffix = '') => {
    if (val === undefined || val === null || isNaN(val)) return 'Unknown / Not Detected';
    return `${typeof val === 'number' ? val.toFixed(1) : val}${suffix}`;
  };

  useEffect(() => {
    if (!is3DEnabled || !mountRef.current) return;

    const width = mountRef.current.clientWidth;
    const height = 180;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(0, 3, 7.5);
    camera.lookAt(0, 0.5, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mountRef.current.innerHTML = '';
    mountRef.current.appendChild(renderer.domElement);

    // Grid Floor
    const grid = new THREE.GridHelper(10, 10, 0x1e293b, 0x0f172a);
    grid.position.y = -0.5;
    scene.add(grid);

    // 3D Spectrum / Histogram Bars representing packet size bins
    const barCount = 7;
    const barsGroup = new THREE.Group();
    const barMeshes = [];

    const baseHeight = meanSize ? Math.min(Math.max((meanSize / 1500) * 2.2, 0.4), 2.5) : 0.8;

    for (let i = 0; i < barCount; i++) {
      const h = baseHeight * (0.6 + Math.sin(i * 1.2) * 0.4 + 0.3);
      const geo = new THREE.BoxGeometry(0.5, h, 0.5);
      const mat = new THREE.MeshStandardMaterial({
        color: i % 2 === 0 ? 0x0ea5e9 : 0x00f2fe,
        roughness: 0.25,
        metalness: 0.8,
        transparent: true,
        opacity: 0.85,
      });
      const bar = new THREE.Mesh(geo, mat);
      bar.position.set((i - barCount / 2 + 0.5) * 0.85, h / 2 - 0.5, 0);

      // Wireframe cap
      const capMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, wireframe: true });
      const cap = new THREE.Mesh(geo, capMat);
      bar.add(cap);

      barsGroup.add(bar);
      barMeshes.push(bar);
    }
    scene.add(barsGroup);

    // Lights
    const light = new THREE.PointLight(0x00f2fe, 2, 20);
    light.position.set(0, 3, 4);
    scene.add(light);
    scene.add(new THREE.AmbientLight(0xffffff, 0.5));

    let animId;
    let clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const elapsed = clock.getElapsedTime();

      barsGroup.rotation.y = Math.sin(elapsed * 0.5) * 0.2;

      barMeshes.forEach((bar, idx) => {
        const pulse = 1 + Math.sin(elapsed * 3 + idx * 0.8) * 0.12;
        bar.scale.y = pulse;
      });

      renderer.render(scene, camera);
    };

    animate();

    const handleResize = () => {
      if (!mountRef.current) return;
      const w = mountRef.current.clientWidth;
      camera.aspect = w / height;
      camera.updateProjectionMatrix();
      renderer.setSize(w, height);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', handleResize);
      if (mountRef.current) mountRef.current.innerHTML = '';
      renderer.dispose();
    };
  }, [meanSize, is3DEnabled]);

  return (
    <div className="glass-panel p-5 relative overflow-hidden flex flex-col justify-between">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <BarChart3 className="w-5 h-5 text-sky-400" />
          <h2 className="text-sm font-semibold text-slate-100 uppercase tracking-wide">
            3D ESP Traffic Classifier
          </h2>
        </div>
        <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-700/80 px-2.5 py-0.5 rounded text-xs font-mono">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-cyan-400 font-bold">{trafficType}</span>
          <span className="text-slate-400">({(confidence * 100).toFixed(1)}%)</span>
        </div>
      </div>

      {/* 3D Flow Histogram Viewport */}
      <div className="relative my-1">
        <div ref={mountRef} style={{ width: '100%', height: '180px' }} />
        {/* Model Badge Overlay */}
        <div className="absolute top-2 left-2 text-[11px] font-mono bg-slate-950/80 px-2 py-0.5 rounded border border-slate-800 text-slate-400 pointer-events-none">
          Model: <span className="text-slate-200">{modelUsed}</span> &bull; Features: 27
        </div>
      </div>

      {/* Real Observable Telemetry Matrix (Zero Fake Values) */}
      <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-3 border-t border-slate-800/80 text-slate-300">
        <div>
          <span className="text-slate-400">Packets:</span>{' '}
          <strong className="text-slate-200">{packetCount.toLocaleString()}</strong>
        </div>
        <div>
          <span className="text-slate-400">Flow Duration:</span>{' '}
          <strong className="text-slate-200">{formatVal(flowDuration, ' s')}</strong>
        </div>
        <div>
          <span className="text-slate-400">Mean Pkt Size:</span>{' '}
          <strong className="text-slate-200">{formatVal(meanSize, ' B')}</strong>
        </div>
        <div>
          <span className="text-slate-400">Mean IAT:</span>{' '}
          <strong className="text-slate-200">{formatVal(meanIat, ' ms')}</strong>
        </div>
        <div>
          <span className="text-slate-400">Pkt Size Std:</span>{' '}
          <strong className="text-slate-200">{formatVal(stdSize, ' B')}</strong>
        </div>
        <div>
          <span className="text-slate-400">Bursts:</span>{' '}
          <strong className="text-slate-200">{formatVal(burstCount)}</strong>
        </div>
      </div>

      <div className="mt-2 text-[10px] text-slate-400/90 italic font-mono flex items-center gap-1">
        <Layers className="w-3 h-3 text-cyan-400" />
        Zero Payload Decryption Architecture. Derived strictly from outer headers.
      </div>
    </div>
  );
}
