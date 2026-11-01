import { useEffect, useRef } from "react";
import { useReducedMotion } from "motion/react";

// The assistant's identity mark: a looping glowing orb. Shipped as a muted,
// autoplaying H.264 clip rather than an animated GIF — same visual result, but
// 19KB instead of the several megabytes the equivalent GIF costs at this size
// and length, and without GIF's 256-colour banding on the gradients.
//
// Both files live in public/ so they're served as plain static assets.
const ORB_VIDEO = "/assistant-orb.mp4";
const ORB_POSTER = "/assistant-orb.webp";

// The source clip is 256x256 with the orb rendered small inside it: sampled
// across the loop, the orb spans 0.62–0.68 of the frame and the rest is flat
// black. Dropped into a circular mask that reads as a black ring around a
// too-small orb, so the media is zoomed to crop the padding away.
//
// 1/0.68 = 1.47 would make the widest pulse touch the edge exactly; 1.45 keeps
// a hair of margin so nothing clips on a frame between the ones sampled.
const ORB_ZOOM = 1.45;
// The orb also sits 4px above centre in the frame (4/256 = 1.6%), so it is
// nudged back down before the zoom rather than ending up visibly high.
const ORB_TRANSFORM = `scale(${ORB_ZOOM}) translateY(1.6%)`;

/**
 * Decorative by design — every caller already labels its own control (the
 * launcher button, the panel header), so this is always aria-hidden rather
 * than announcing itself a second time to a screen reader.
 *
 * Honours prefers-reduced-motion with a still frame, matching the global
 * motion policy in styles.css ("users who ask for reduced motion get the
 * static final state") and the useReducedMotion() approach already used for
 * JS-driven motion on the landing page.
 *
 * `className` lands on a clipping wrapper rather than on the media itself.
 * Callers use this two ways — as a sized circle of its own (`h-8 w-8
 * rounded-full`) and as a fill inside someone else's circle (`h-full w-full`)
 * — and the zoom above has to be clipped by the shape in both cases. Scaling
 * the media element directly would grow the first kind instead of zooming it.
 */
export function AssistantOrb({ className = "" }: { className?: string }) {
  const reduceMotion = useReducedMotion();
  const videoRef = useRef<HTMLVideoElement>(null);

  // React has a long-standing quirk where the `muted` prop isn't reliably
  // reflected onto the DOM property, and an unmuted video is blocked from
  // autoplaying — which would leave a dead black circle. Set it directly.
  useEffect(() => {
    if (videoRef.current) videoRef.current.muted = true;
  }, [reduceMotion]);

  return (
    <span aria-hidden className={`relative block overflow-hidden ${className}`}>
      {reduceMotion ? (
        <img
          src={ORB_POSTER}
          alt=""
          draggable={false}
          className="absolute inset-0 h-full w-full object-cover"
          style={{ transform: ORB_TRANSFORM }}
        />
      ) : (
        <video
          ref={videoRef}
          src={ORB_VIDEO}
          poster={ORB_POSTER}
          autoPlay
          loop
          muted
          playsInline
          preload="auto"
          tabIndex={-1}
          className="absolute inset-0 h-full w-full object-cover"
          style={{ transform: ORB_TRANSFORM }}
        />
      )}
    </span>
  );
}
