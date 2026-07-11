import React, { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { colors, font, SEV_COLOR } from '../lib/tokens';

let _addToast = null;

export function toast(event) {
  _addToast?.(event);
}

export default function Toasts() {
  const [toasts, setToasts] = useState([]);

  _addToast = useCallback((event) => {
    const id = Date.now();
    setToasts(t => [{ ...event, _id: id }, ...t.slice(0, 4)]);
    setTimeout(() => setToasts(t => t.filter(x => x._id !== id)), 5000);
  }, []);

  return (
    <div style={{
      position: 'fixed',
      bottom: 16,
      right: 16,
      zIndex: 999,
      display: 'flex',
      flexDirection: 'column',
      gap: 6,
    }}>
      <AnimatePresence>
        {toasts.map(t => {
          const color = SEV_COLOR[t.severity] || colors.green;
          return (
            <motion.div
              key={t._id}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.2 }}
              style={{
                fontFamily: font.mono,
                fontSize: 9,
                letterSpacing: 1,
                padding: '9px 13px',
                borderRadius: 2,
                background: colors.bg2,
                borderLeft: `2px solid ${color}`,
                maxWidth: 260,
                boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
              }}
            >
              <div style={{ color, marginBottom: 2 }}>
                {(t.severity || '').toUpperCase()} — {(t.event_type || '').replace(/_/g, ' ')}
              </div>
              <div style={{ color: colors.muted, fontSize: 8 }}>
                {(t.title || '').slice(0, 55)}
              </div>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}