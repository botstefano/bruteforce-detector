import React, { useEffect, useRef, useState } from 'react';
import { RotateCw, Volume2 } from 'lucide-react';

interface RealCaptchaCanvasProps {
  onCaptchaReady: (captchaId: string) => void;
  resetTrigger?: number;
}

export const RealCaptchaCanvas: React.FC<RealCaptchaCanvasProps> = ({
  onCaptchaReady,
  resetTrigger = 0,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [loading, setLoading] = useState(false);
  const [currentCode, setCurrentCode] = useState('');
  const [captchaId, setCaptchaId] = useState('');

  const cargarNuevoCaptcha = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/captcha/nuevo');
      if (!res.ok) throw new Error('Error al generar captcha');
      const data = await res.json();
      setCaptchaId(data.captchaId);
      setCurrentCode(data.code);
      onCaptchaReady(data.captchaId);
      dibujarCaptchaEnCanvas(data.code);
    } catch (err) {
      console.error('Error cargando captcha:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    cargarNuevoCaptcha();
  }, [resetTrigger]);

  const dibujarCaptchaEnCanvas = (code: string) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;

    // 1. Fondo oscuro con gradiente
    const grad = ctx.createLinearGradient(0, 0, width, height);
    grad.addColorStop(0, '#020617');
    grad.addColorStop(0.5, '#0f172a');
    grad.addColorStop(1, '#1e1b4b');
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, width, height);

    // 2. Líneas de interferencia aleatorias (anti-OCR)
    const lineColors = ['#06b6d4', '#8b5cf6', '#ec4899', '#10b981', '#f59e0b', '#3b82f6'];
    for (let i = 0; i < 7; i++) {
      ctx.beginPath();
      ctx.strokeStyle = lineColors[i % lineColors.length] + '40'; // 25% opacidad
      ctx.lineWidth = Math.random() * 2 + 1;
      ctx.moveTo(Math.random() * width, Math.random() * height);
      ctx.bezierCurveTo(
        Math.random() * width,
        Math.random() * height,
        Math.random() * width,
        Math.random() * height,
        Math.random() * width,
        Math.random() * height
      );
      ctx.stroke();
    }

    // 3. Puntos de ruido estático (Salt & Pepper)
    for (let i = 0; i < 50; i++) {
      ctx.fillStyle = Math.random() > 0.5 ? '#ffffff20' : '#38bdf820';
      ctx.beginPath();
      ctx.arc(Math.random() * width, Math.random() * height, Math.random() * 1.5, 0, Math.PI * 2);
      ctx.fill();
    }

    // 4. Dibujar cada carácter con rotación, distorsión y color aleatorio
    const coloresTexto = ['#38bdf8', '#c084fc', '#4ade80', '#fb7185', '#facc15', '#67e8f9'];
    const fuentes = ['monospace', 'sans-serif', 'Courier New', 'Arial'];
    const len = code.length;
    const pasoX = (width - 40) / len;

    for (let i = 0; i < len; i++) {
      const char = code[i];
      const x = 25 + i * pasoX + (Math.random() * 6 - 3);
      const y = height / 2 + 8 + (Math.random() * 8 - 4);
      const angulo = (Math.random() - 0.5) * 0.45; // -13° a +13° aprox
      const fuente = fuentes[Math.floor(Math.random() * fuentes.length)];
      const color = coloresTexto[Math.floor(Math.random() * coloresTexto.length)];

      ctx.save();
      ctx.translate(x, y);
      ctx.rotate(angulo);

      ctx.font = `bold ${Math.floor(Math.random() * 6 + 26)}px ${fuente}`;
      ctx.fillStyle = color;
      ctx.shadowColor = color;
      ctx.shadowBlur = 6;
      ctx.fillText(char, 0, 0);

      ctx.restore();
    }

    // 5. Línea ondulada horizontal de corte (strike-through curve)
    ctx.beginPath();
    ctx.strokeStyle = '#ffffff30';
    ctx.lineWidth = 1.5;
    ctx.moveTo(10, height / 2 + Math.sin(0) * 8);
    for (let x = 10; x < width - 10; x += 5) {
      ctx.lineTo(x, height / 2 + Math.sin(x * 0.08) * 10);
    }
    ctx.stroke();
  };

  const reproducirAudio = () => {
    if (!currentCode || !('speechSynthesis' in window)) return;
    window.speechSynthesis.cancel();
    // Deletrear con espacios para pronunciación clara
    const textoDeletreado = currentCode.split('').join('. ');
    const utter = new SpeechSynthesisUtterance(textoDeletreado);
    utter.rate = 0.75;
    utter.pitch = 1.0;
    utter.lang = 'es-ES';
    window.speechSynthesis.speak(utter);
  };

  return (
    <div className="flex flex-col space-y-2 select-none">
      <div className="flex items-center space-x-2">
        <div className="relative rounded-xl overflow-hidden border border-slate-700 bg-slate-950 shadow-inner">
          <canvas
            ref={canvasRef}
            width={220}
            height={65}
            className="block cursor-pointer"
            onClick={cargarNuevoCaptcha}
            title="Haz clic para recargar el CAPTCHA"
          />
          {loading && (
            <div className="absolute inset-0 bg-slate-950/80 flex items-center justify-center text-xs text-cyan-400 font-bold">
              Generando desafío...
            </div>
          )}
        </div>

        <div className="flex flex-col space-y-1">
          <button
            type="button"
            onClick={cargarNuevoCaptcha}
            disabled={loading}
            title="Recargar nuevo desafío CAPTCHA"
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 rounded-lg border border-slate-700 transition-all flex items-center justify-center"
          >
            <RotateCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            type="button"
            onClick={reproducirAudio}
            disabled={loading || !currentCode}
            title="Escuchar código CAPTCHA por voz"
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-emerald-400 rounded-lg border border-slate-700 transition-all flex items-center justify-center"
          >
            <Volume2 className="w-4 h-4" />
          </button>
        </div>
      </div>
      <p className="text-[10px] text-slate-400">
        Desafío gráfico anti-bot con distorsión visual y validación criptográfica en servidor.
      </p>
    </div>
  );
};
