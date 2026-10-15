import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { UploadCloud, CheckCircle2, Loader2, FileCode, Play, AlertCircle } from 'lucide-react';

export default function PcapAnalyzer3D({ onAnalyzeFile, onSelectPreset, isAnalyzing = false, is3DEnabled = true }) {
  const mountRef = useRef(null);
  const [state, setState] = useState('IDLE'); // IDLE, UPLOADING, ANALYZING, PROCESSING, COMPLETE
  const [fileName, setFileName] = useState('');
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef(null);
  const sphereRef = useRef(null);

  useEffect(() => {
    if (isAnalyzing) {
      setState('ANALYZING');
      const timer1 = setTimeout(() => setState('PROCESSING'), 1200);
      return () => clearTimeout(timer1);
    }
  }, [isAnalyzing]);

  useEffect(() => {
    if (!is3DEnabled || !mountRef.current) return;

    const width = mountRef.current.clientWidth;
    const height = 180;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(0, 0, 5.5);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mountRef.current.innerHTML = '';
    mountRef.current.appendChild(renderer.domElement);

    // Floating Cybersecurity Data Core (Wireframe Dodecahedron + Glowing Particle Cloud)
    const coreGeo = new THREE.DodecahedronGeometry(1.25, 1);
    const coreMat = new THREE.MeshBasicMaterial({
      color: state === 'COMPLETE' ? 0x10b981 : state === 'ANALYZING' || state === 'PROCESSING' ? 0x00f2fe : 0x0ea5e9,
      wireframe: true,
      transparent: true,
      opacity: 0.65,
    });
    const core = new THREE.Mesh(coreGeo, coreMat);
    scene.add(core);
    sphereRef.current = core;

    // Inner Solid Core
    const innerGeo = new THREE.IcosahedronGeometry(0.65, 0);
    const innerMat = new THREE.MeshStandardMaterial({
      color: 0x0f172a,
      roughness: 0.3,
      metalness: 0.8,
    });
    const inner = new THREE.Mesh(innerGeo, innerMat);
    scene.add(inner);

    // Swirling Particle Dust
    const particleCount = 60;
    const pGeo = new THREE.BufferGeometry();
    const pPos = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount; i++) {
      const radius = 1.6 + Math.random() * 0.8;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.random() * Math.PI;
      pPos[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
      pPos[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
      pPos[i * 3 + 2] = radius * Math.cos(phi);
    }
    pGeo.setAttribute('position', new THREE.BufferAttribute(pPos, 3));
    const pMat = new THREE.PointsMaterial({
      color: state === 'ANALYZING' ? 0x00f2fe : 0x38bdf8,
      size: 0.08,
      transparent: true,
      opacity: 0.8,
    });
    const pCloud = new THREE.Points(pGeo, pMat);
    scene.add(pCloud);

    // Lights
    const pLight = new THREE.PointLight(0x00f2fe, 2, 20);
    pLight.position.set(0, 2, 3);
    scene.add(pLight);
    scene.add(new THREE.AmbientLight(0xffffff, 0.4));

    let animId;
    let clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const elapsed = clock.getElapsedTime();

      const speedMultiplier = state === 'ANALYZING' || state === 'PROCESSING' ? 3.0 : 1.0;
      core.rotation.y = elapsed * 0.4 * speedMultiplier;
      core.rotation.x = elapsed * 0.25 * speedMultiplier;
      inner.rotation.y = -elapsed * 0.6 * speedMultiplier;

      pCloud.rotation.y = elapsed * 0.2 * speedMultiplier;

      const pulse = 1 + Math.sin(elapsed * 2.5 * speedMultiplier) * 0.08;
      core.scale.set(pulse, pulse, pulse);

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
  }, [state, is3DEnabled]);

  const handleDrop = (e) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelected = (file) => {
    setFileName(file.name);
    setState('UPLOADING');
    setTimeout(() => {
      setState('ANALYZING');
      onAnalyzeFile(file)
        .then(() => setState('COMPLETE'))
        .catch(() => setState('IDLE'));
    }, 400);
  };

  return (
    <div className="glass-panel p-5 relative overflow-hidden flex flex-col justify-between">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <FileCode className="w-5 h-5 text-sky-400" />
          <h2 className="text-sm font-semibold text-slate-100 uppercase tracking-wide">
            3D PCAP Core Analyzer
          </h2>
        </div>
        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
          STATE: <strong className="text-cyan-400">{state}</strong>
        </span>
      </div>

      {/* 3D Holographic Data Core */}
      <div 
        className={`relative my-1 cursor-pointer border-2 border-dashed rounded-xl transition-all duration-300 ${
          dragActive ? 'border-cyan-400 bg-sky-500/10' : 'border-slate-800/80 hover:border-slate-700 bg-slate-950/40'
        }`}
        onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
        onDragLeave={() => setDragActive(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
      >
        <input 
          ref={fileInputRef} 
          type="file" 
          accept=".pcap,.pcapng,.cap" 
          className="hidden" 
          onChange={(e) => e.target.files?.[0] && handleFileSelected(e.target.files[0])}
        />

        <div ref={mountRef} style={{ width: '100%', height: '180px' }} />

        {/* Center Prompt Overlay */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none p-4 text-center">
          {state === 'IDLE' && (
            <>
              <UploadCloud className="w-8 h-8 text-cyan-400 mb-1.5 animate-bounce" />
              <div className="text-xs font-semibold text-slate-200">
                Drop IPsec PCAP into Data Core
              </div>
              <div className="text-[10px] text-slate-400 mt-0.5">
                or click to browse local files (.pcap, .pcapng)
              </div>
            </>
          )}

          {state === 'UPLOADING' && (
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs">
              <Loader2 className="w-4 h-4 animate-spin" /> Ingesting capture data...
            </div>
          )}

          {(state === 'ANALYZING' || state === 'PROCESSING') && (
            <div className="flex flex-col items-center text-cyan-400 font-mono text-xs">
              <Loader2 className="w-5 h-5 animate-spin mb-1 text-cyan-400" />
              <span>{state === 'ANALYZING' ? 'Dissecting IKEv2 & ESP headers...' : 'Executing ML & Rule Evaluation...'}</span>
              <span className="text-[10px] text-slate-400 mt-1">{fileName}</span>
            </div>
          )}

          {state === 'COMPLETE' && (
            <div className="flex flex-col items-center text-emerald-400 font-mono text-xs">
              <CheckCircle2 className="w-6 h-6 mb-1 text-emerald-400" />
              <span>Assessment Complete</span>
              <span className="text-[10px] text-slate-300 mt-0.5 truncate max-w-[200px]">{fileName}</span>
            </div>
          )}
        </div>
      </div>

      {/* Preset Demo Buttons */}
      <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
        <span className="text-slate-400 font-mono text-[11px]">Instant Presets:</span>
        <div className="flex gap-2">
          <button 
            type="button"
            onClick={(e) => { e.stopPropagation(); onSelectPreset('compliant'); }}
            className="px-2.5 py-1 rounded bg-emerald-950/40 text-emerald-300 border border-emerald-800/60 hover:bg-emerald-900/60 transition-colors flex items-center gap-1 font-mono text-[11px]"
          >
            <Play className="w-3 h-3 fill-emerald-300" /> Compliant
          </button>
          <button 
            type="button"
            onClick={(e) => { e.stopPropagation(); onSelectPreset('weak'); }}
            className="px-2.5 py-1 rounded bg-amber-950/40 text-amber-300 border border-amber-800/60 hover:bg-amber-900/60 transition-colors flex items-center gap-1 font-mono text-[11px]"
          >
            <Play className="w-3 h-3 fill-amber-300" /> Vulnerable
          </button>
        </div>
      </div>
    </div>
  );
}
