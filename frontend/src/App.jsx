import React, { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { colors } from './lib/tokens';
import { useStats, useEvents, useWebSocket } from './hooks/useApi';
import Topbar from './components/Topbar';
import Sidebar from './components/Sidebar';
import EventStream from './components/EventStream';
import Analyst from './components/Analyst';
import Toasts, { toast } from './components/Toasts';

export default function App() {
  const [filter, setFilter] = useState('all');
  const [pendingEvent, setPendingEvent] = useState(null);
  const { stats, sysStats, refresh: refreshStats } = useStats();
  const { events, loading, refresh: refreshEvents } = useEvents(filter === 'all' ? null : filter);

  const handleWsEvent = useCallback((msg) => {
    if (msg.type === 'new_event') {
      toast(msg.data);
      refreshEvents();
      refreshStats();
    }
  }, [refreshEvents, refreshStats]);

  useWebSocket(handleWsEvent);

  function handleFilterChange(f) {
    setFilter(f);
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
      style={{
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        background: colors.bg,
        overflow: 'hidden',
      }}
    >
      <Topbar stats={stats} />

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <Sidebar
          stats={stats}
          sysStats={sysStats}
          onGenerateReport={() => setPendingEvent({ id: '__report__' })}
          onFilterCritical={() => handleFilterChange('critical')}
          onFilterAll={() => handleFilterChange('all')}
        />

        <EventStream
          events={events}
          loading={loading}
          filter={filter}
          onFilterChange={handleFilterChange}
          onSelectEvent={(ev) => setPendingEvent(ev)}
        />

        <Analyst
          pendingEvent={pendingEvent?.id !== '__report__' ? pendingEvent : null}
          onPendingClear={() => setPendingEvent(null)}
        />
      </div>

      <Toasts />
    </motion.div>
  );
}