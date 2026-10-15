import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { Shield, ShieldCheck, AlertTriangle, AlertOctagon, HelpCircle } from 'lucide-react';

export default function SecurityScore3D({ assessment, is3DEnabled = true }) {
  const mountRef = useRef(null);

  const riskScore = assessment?.risk_score ?? 15;
  const severity = assessment?.severity || 'LOW';
  const subScores = assessment?.sub_scores || {
    crypto_risk: 0,
    key_exchange_risk: 0,
    configuration_risk: 0,
    metadata_exposure_risk: 15,
  };

  // Color mapping matching Phase 3 specs
  // 0-24: LOW, 25-49: LOW-MEDIUM, 50-74: MEDIUM, 75-89: HIGH, 90-100: CRITICAL
  const getThemeColor = (score) => {
    if (score >= 90) return { hex: 0xf43f5e, str: '#f43f5e', bg: 'rgba(244, 63, 94, 0.15)', name: 'CRITICAL' };
    if (score >= 75) return { hex: 0xf97316, str: '#f97316', bg: 'rgba(249, 115, 22, 0.15)', name: 'HIGH' };
    if (score >= 50) return { hex: 0xf59e0b, str: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)', name: 'MEDIUM' };
    if (score >= 25) return { hex: 0x0ea5e9, str: '#0ea5e9', bg: 'rgba(14, 165, 233, 0.15)', name: 'LOW-MEDIUM' };
    return { hex: 0x10b981, str: '#10b981', bg: 'rgba(16, 185, 129, 0.15)', name: 'LOW / SECURE' };
  };

  const theme = getThemeColor(riskScore);

  useEffect(() => {
    if (!is3DEnabled || !mountRef.current) return;

    const width = mountRef.current.clientWidth;
    const height = 220;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(0, 0, 7.5);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mountRef.current.innerHTML = '';
    mountRef.current.appendChild(renderer.domElement);

    // Outer Gyro Ring 1
    const ring1Geo = new THREE.TorusGeometry(2.3, 0.05, 12, 48);
    const ring1Mat = new THREE.MeshBasicMaterial({ color: theme.hex, wireframe: true, transparent: true, opacity: 0.6 });
    const ring1 = new THREE.Mesh(ring1Geo, ring1Mat);
    scene.add(ring1);

    // Middle Ring 2 (Counter rotating)
    const ring2Geo = new THREE.TorusGeometry(1.9, 0.04, 8, 36);
    const ring2Mat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.5 });
    const ring2 = new THREE.Mesh(ring2Geo, ring2Mat);
    scene.add(ring2);

    // Inner Arc (Score proportion)
    const arcAngle = (riskScore / 100) * (Math.PI * 2);
    const ring3Geo = new THREE.RingGeometry(1.4, 1.6, 32, 1, 0, Math.max(arcAngle, 0.2));
    const ring3Mat = new THREE.MeshBasicMaterial({
      color: theme.hex,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.85,
    });
    const ring3 = new THREE.Mesh(ring3Geo, ring3Mat);
    scene.add(ring3);

    // Central Floating Core (Octahedron)
    const coreGeo = new THREE.OctahedronGeometry(0.85, 0);
    const coreMat = new THREE.MeshStandardMaterial({
      color: 0x0f172a,
      roughness: 0.2,
      metalness: 0.9,
    });
    const core = new THREE.Mesh(coreGeo, coreMat);
    scene.add(core);

    const coreWireGeo = new THREE.OctahedronGeometry(0.88, 0);
    const coreWireMat = new THREE.MeshBasicMaterial({ color: theme.hex, wireframe: true });
    const coreWire = new THREE.Mesh(coreWireGeo, coreWireMat);
    scene.add(coreWire);

    // Light
    const light = new THREE.PointLight(theme.hex, 2, 20);
    light.position.set(0, 2, 3);
    scene.add(light);
    scene.add(new THREE.AmbientLight(0xffffff, 0.5));

    let animId;
    let clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const elapsed = clock.getElapsedTime();

      ring1.rotation.x = elapsed * 0.4;
      ring1.rotation.y = elapsed * 0.5;

      ring2.rotation.x = -elapsed * 0.6;
      ring2.rotation.z = elapsed * 0.3;

      core.rotation.y = elapsed * 0.8;
      core.rotation.x = elapsed * 0.4;
      coreWire.rotation.y = elapsed * 0.8;
      coreWire.rotation.x = elapsed * 0.4;

      const breathe = 1 + Math.sin(elapsed * 2.5) * 0.06;
      core.scale.set(breathe, breathe, breathe);
      coreWire.scale.set(breathe, breathe, breathe);

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
  }, [riskScore, theme.hex, is3DEnabled]);

  return (
    <div className="glass-panel p-5 relative overflow-hidden flex flex-col justify-between">
      {/* Title Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {riskScore <= 24 ? (
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          ) : riskScore <= 74 ? (
            <AlertTriangle className="w-5 h-5 text-amber-400" />
          ) : (
            <AlertOctagon className="w-5 h-5 text-rose-500" />
          )}
          <h2 className="text-sm font-semibold text-slate-100 uppercase tracking-wide">
            3D Security Risk Core
          </h2>
        </div>
        <span 
          className="text-xs px-2.5 py-1 rounded-md font-mono font-bold uppercase tracking-wider"
          style={{ background: theme.bg, color: theme.str, border: `1px solid ${theme.str}55` }}
        >
          {severity}
        </span>
      </div>

      {/* 3D Core Viewport */}
      <div className="relative my-2">
        <div ref={mountRef} style={{ width: '100%', height: '220px' }} />
        {/* Floating Numeric Score Badge */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <div className="text-4xl font-extrabold font-mono tracking-tight" style={{ color: theme.str }}>
            {riskScore}
          </div>
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-widest mt-0.5">
            / 100 Risk Score
          </div>
        </div>
      </div>

      {/* Explainable Deterministic Sub-Scores Breakdown */}
      <div className="space-y-2 pt-2 border-t border-slate-800/80 text-xs font-mono">
        <div className="flex justify-between items-center text-slate-300">
          <span className="text-slate-400">Crypto Risk:</span>
          <span className={subScores.crypto_risk > 0 ? 'text-amber-400 font-bold' : 'text-emerald-400 font-bold'}>
            +{subScores.crypto_risk} pts
          </span>
        </div>
        <div className="flex justify-between items-center text-slate-300">
          <span className="text-slate-400">Key Exchange Risk:</span>
          <span className={subScores.key_exchange_risk > 0 ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
            +{subScores.key_exchange_risk} pts
          </span>
        </div>
        <div className="flex justify-between items-center text-slate-300">
          <span className="text-slate-400">Config / PFS Risk:</span>
          <span className={subScores.configuration_risk > 0 ? 'text-amber-400 font-bold' : 'text-emerald-400 font-bold'}>
            +{subScores.configuration_risk} pts
          </span>
        </div>
        <div className="flex justify-between items-center text-slate-300">
          <span className="text-slate-400">Metadata Exposure:</span>
          <span className="text-sky-400 font-bold">
            +{subScores.metadata_exposure_risk} pts
          </span>
        </div>
      </div>
    </div>
  );
}
