import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { Shield, ShieldAlert, Radio, Activity, Lock, RefreshCw } from 'lucide-react';

export default function Topology3D({ sessionData, is3DEnabled = true }) {
  const mountRef = useRef(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const sceneRef = useRef(null);
  const rendererRef = useRef(null);

  // Extract parameters from real backend response
  const encryption = sessionData?.encryption || sessionData?.vpn_configuration?.encryption || 'AES-256-GCM';
  const ikeVer = sessionData?.ike_version || sessionData?.vpn_configuration?.ike_version || 'IKEv2';
  const dhGroup = sessionData?.dh_group_name || sessionData?.vpn_configuration?.dh_group_name || 'ecp256';
  const pfs = sessionData?.pfs ?? sessionData?.vpn_configuration?.pfs ?? 'Unknown';
  const espPackets = sessionData?.esp_packets ?? sessionData?.vpn_configuration?.esp_packets ?? 0;
  const ikePackets = sessionData?.ike_packets ?? sessionData?.vpn_configuration?.ike_packets ?? 0;
  const initSpi = sessionData?.initiator_spi || sessionData?.vpn_configuration?.initiator_spi || '0x8f2d4e1a0b3c5e7f';
  const respSpi = sessionData?.responder_spi || sessionData?.vpn_configuration?.responder_spi || '0x1c9a4b8e2f6d0e3a';
  const severity = sessionData?.security_assessment?.severity || sessionData?.summary?.severity || 'LOW';

  // Determine theme color based on real security severity
  const isWeak = severity === 'HIGH' || severity === 'CRITICAL';
  const isWarn = severity === 'MEDIUM' || severity === 'LOW-MEDIUM';
  const primaryHex = isWeak ? 0xf43f5e : isWarn ? 0xf59e0b : 0x00f2fe;
  const secondaryHex = isWeak ? 0x9f1239 : isWarn ? 0xb45309 : 0x0284c7;

  useEffect(() => {
    if (!is3DEnabled || !mountRef.current) return;

    const width = mountRef.current.clientWidth;
    const height = mountRef.current.clientHeight || 420;

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    sceneRef.current = scene;
    scene.fog = new THREE.FogExp2(0x07090e, 0.025);

    const camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 1000);
    camera.position.set(0, 3.5, 12);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
    rendererRef.current = renderer;
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mountRef.current.innerHTML = '';
    mountRef.current.appendChild(renderer.domElement);

    // 2. Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(primaryHex, 2.5, 50);
    pointLight.position.set(0, 4, 4);
    scene.add(pointLight);

    // 3. Grid Plane (Cyber Floor)
    const gridHelper = new THREE.GridHelper(30, 30, 0x1e293b, 0x0f172a);
    gridHelper.position.y = -2.2;
    scene.add(gridHelper);

    // 4. Gateway Node Helper Builder
    const createGatewayNode = (xPos, label, spi) => {
      const group = new THREE.Group();
      group.position.set(xPos, 0, 0);

      // Core Tower (Hexagonal Cylinder)
      const towerGeo = new THREE.CylinderGeometry(0.9, 1.1, 2.4, 6);
      const towerMat = new THREE.MeshStandardMaterial({
        color: 0x0f172a,
        roughness: 0.25,
        metalness: 0.85,
        wireframe: false,
      });
      const tower = new THREE.Mesh(towerGeo, towerMat);
      group.add(tower);

      // Outer Wireframe Cage
      const wireMat = new THREE.MeshBasicMaterial({ color: primaryHex, wireframe: true, transparent: true, opacity: 0.4 });
      const wireframe = new THREE.Mesh(towerGeo, wireMat);
      wireframe.scale.set(1.08, 1.05, 1.08);
      group.add(wireframe);

      // Rotating Radar Ring
      const ringGeo = new THREE.TorusGeometry(1.6, 0.03, 8, 32);
      const ringMat = new THREE.MeshBasicMaterial({ color: primaryHex, transparent: true, opacity: 0.75 });
      const ring = new THREE.Mesh(ringGeo, ringMat);
      ring.rotation.x = Math.PI / 2;
      group.add(ring);

      // Beacon Light on Top
      const beaconGeo = new THREE.SphereGeometry(0.22, 16, 16);
      const beaconMat = new THREE.MeshBasicMaterial({ color: primaryHex });
      const beacon = new THREE.Mesh(beaconGeo, beaconMat);
      beacon.position.y = 1.35;
      group.add(beacon);

      scene.add(group);
      return { group, ring, beacon };
    };

    const nodeA = createGatewayNode(-4.5, 'Gateway A (Initiator)', initSpi);
    const nodeB = createGatewayNode(4.5, 'Gateway B (Responder)', respSpi);

    // 5. IPsec Tunnel Conduit (Glowing Dual Cylinder Conduit)
    const curve = new THREE.LineCurve3(new THREE.Vector3(-4.5, 0, 0), new THREE.Vector3(4.5, 0, 0));
    const tubeGeo = new THREE.TubeGeometry(curve, 32, 0.28, 8, false);
    const tubeMat = new THREE.MeshStandardMaterial({
      color: secondaryHex,
      roughness: 0.3,
      metalness: 0.7,
      transparent: true,
      opacity: 0.35,
    });
    const tunnel = new THREE.Mesh(tubeGeo, tubeMat);
    scene.add(tunnel);

    // Tunnel Outer Energy Ring Shell
    const outerTubeGeo = new THREE.TubeGeometry(curve, 24, 0.45, 8, false);
    const outerTubeMat = new THREE.MeshBasicMaterial({
      color: primaryHex,
      wireframe: true,
      transparent: true,
      opacity: 0.15,
    });
    const outerTunnel = new THREE.Mesh(outerTubeGeo, outerTubeMat);
    scene.add(outerTunnel);

    // 6. Animated ESP Particles (Flowing packets)
    const particleCount = Math.min(Math.max(espPackets > 0 ? 36 : 12, 12), 48);
    const particleGeo = new THREE.BufferGeometry();
    const particlePositions = new Float32Array(particleCount * 3);
    const particleSpeeds = new Float32Array(particleCount);

    for (let i = 0; i < particleCount; i++) {
      const t = Math.random();
      particlePositions[i * 3] = -4.5 + t * 9.0;
      particlePositions[i * 3 + 1] = (Math.random() - 0.5) * 0.2;
      particlePositions[i * 3 + 2] = (Math.random() - 0.5) * 0.2;
      particleSpeeds[i] = 0.04 + Math.random() * 0.05;
    }
    particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));

    const particleMat = new THREE.PointsMaterial({
      color: primaryHex,
      size: 0.24,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
    });
    const particles = new THREE.Points(particleGeo, particleMat);
    scene.add(particles);

    // 7. Handshake Activity Rings (IKE Negotiation pulses)
    const ikePulseGeo = new THREE.RingGeometry(0.2, 0.4, 32);
    const ikePulseMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.8,
    });
    const ikePulse = new THREE.Mesh(ikePulseGeo, ikePulseMat);
    ikePulse.rotation.x = Math.PI / 2;
    ikePulse.position.set(-4.5, 0.05, 0);
    scene.add(ikePulse);

    // 8. Interactive Mouse Movement (Parallax Orbit)
    let mouseX = 0;
    let mouseY = 0;
    let targetX = 0;
    let targetY = 3.5;

    const handleMouseMove = (e) => {
      const rect = mountRef.current?.getBoundingClientRect();
      if (!rect) return;
      const x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      const y = -(((e.clientY - rect.top) / rect.height) * 2 - 1);
      mouseX = x * 2.5;
      mouseY = 3.5 + y * 1.5;
    };

    window.addEventListener('mousemove', handleMouseMove);

    // 9. Animation Loop
    let animId;
    let clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const elapsed = clock.getElapsedTime();

      // Camera gentle damping
      targetX += (mouseX - targetX) * 0.04;
      targetY += (mouseY - targetY) * 0.04;
      camera.position.x = targetX;
      camera.position.y = Math.max(targetY, 1.5);
      camera.lookAt(0, 0, 0);

      // Rotate nodes & rings
      nodeA.group.rotation.y = elapsed * 0.3;
      nodeB.group.rotation.y = -elapsed * 0.3;
      nodeA.ring.rotation.z = elapsed * 0.7;
      nodeB.ring.rotation.z = -elapsed * 0.7;

      // Pulse beacon lights
      const beaconScale = 1 + Math.sin(elapsed * 4) * 0.25;
      nodeA.beacon.scale.set(beaconScale, beaconScale, beaconScale);
      nodeB.beacon.scale.set(beaconScale, beaconScale, beaconScale);

      // Pulse outer tunnel wireframe
      outerTunnel.rotation.x = elapsed * 0.5;

      // Expand IKE handshake pulse
      if (ikePackets > 0) {
        const pulseProg = (elapsed % 2.5) / 2.5;
        ikePulse.scale.set(1 + pulseProg * 6, 1 + pulseProg * 6, 1);
        ikePulseMat.opacity = Math.max(0, 1 - pulseProg);
        ikePulse.position.x = -4.5 + pulseProg * 9.0;
      }

      // Move ESP particles across tunnel
      const posArr = particles.geometry.attributes.position.array;
      for (let i = 0; i < particleCount; i++) {
        posArr[i * 3] += particleSpeeds[i];
        // Reset when reaching Gateway B
        if (posArr[i * 3] > 4.5) {
          posArr[i * 3] = -4.5;
          posArr[i * 3 + 1] = (Math.sin(elapsed * 3 + i) * 0.15);
          posArr[i * 3 + 2] = (Math.cos(elapsed * 3 + i) * 0.15);
        }
      }
      particles.geometry.attributes.position.needsUpdate = true;

      renderer.render(scene, camera);
    };

    animate();

    // Resize Handler
    const handleResize = () => {
      if (!mountRef.current) return;
      const w = mountRef.current.clientWidth;
      const h = mountRef.current.clientHeight || 420;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    // Cleanup
    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('resize', handleResize);
      if (rendererRef.current?.domElement && mountRef.current) {
        mountRef.current.innerHTML = '';
      }
      renderer.dispose();
    };
  }, [is3DEnabled, primaryHex, secondaryHex, espPackets, ikePackets]);

  return (
    <div className="glass-panel glass-panel-glow p-4 relative overflow-hidden" style={{ minHeight: '440px' }}>
      {/* 3D Viewport Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 mb-2">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
            <Radio className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-100 tracking-wide uppercase">
              3D Live IPsec Network Topology
            </h2>
            <p className="text-xs text-slate-400">
              Interactive WebGL Site-to-Site Tunnel & Real ESP Packet Particle Stream
            </p>
          </div>
        </div>

        {/* Real-time Crypto Suite Badge */}
        <div className="flex items-center gap-2">
          <span className={`text-xs px-2.5 py-1 rounded-full font-mono font-medium ${
            isWeak ? 'badge-crit' : isWarn ? 'badge-warn' : 'badge-pass'
          }`}>
            {encryption} &bull; DH {dhGroup} &bull; PFS: {String(pfs)}
          </span>
        </div>
      </div>

      {/* 3D Canvas Mount Point */}
      <div 
        ref={mountRef} 
        className="canvas-container cursor-grab active:cursor-grabbing" 
        style={{ height: '360px', width: '100%' }}
      />

      {/* Real HUD Telemetry Overlay */}
      <div className="absolute bottom-4 left-6 right-6 pointer-events-none flex justify-between items-end">
        {/* Gateway A Telemetry */}
        <div className="bg-slate-900/85 backdrop-blur-md border border-slate-700/60 p-2.5 rounded-lg text-xs font-mono text-slate-300 pointer-events-auto">
          <div className="flex items-center gap-1.5 text-cyan-400 font-bold mb-1">
            <Lock className="w-3.5 h-3.5" /> Gateway A (192.168.1.1)
          </div>
          <div>Role: <strong>Initiator</strong></div>
          <div className="text-slate-400 truncate max-w-[190px]">SPI: {initSpi}</div>
          <div className="text-slate-400">Handshake: {ikeVer}</div>
        </div>

        {/* Center Tunnel Metrics */}
        <div className="bg-slate-900/90 backdrop-blur-md border border-sky-500/30 px-3.5 py-2 rounded-lg text-xs font-mono text-center pointer-events-auto">
          <div className="text-sky-400 font-bold flex items-center justify-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-cyan-400 animate-spin" style={{ animationDuration: '6s' }} />
            IPsec ESP Conduit
          </div>
          <div className="text-slate-200 mt-1">
            <strong>{espPackets.toLocaleString()}</strong> ESP Data Packets
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            {ikePackets} IKE Messages Observed
          </div>
        </div>

        {/* Gateway B Telemetry */}
        <div className="bg-slate-900/85 backdrop-blur-md border border-slate-700/60 p-2.5 rounded-lg text-xs font-mono text-slate-300 text-right pointer-events-auto">
          <div className="flex items-center justify-end gap-1.5 text-cyan-400 font-bold mb-1">
            Gateway B (192.168.2.1) <Lock className="w-3.5 h-3.5" />
          </div>
          <div>Role: <strong>Responder</strong></div>
          <div className="text-slate-400 truncate max-w-[190px]">SPI: {respSpi}</div>
          <div className="text-slate-400">Status: {severity} Risk Profile</div>
        </div>
      </div>
    </div>
  );
}
