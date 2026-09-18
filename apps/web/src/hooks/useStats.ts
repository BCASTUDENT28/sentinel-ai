import { useState, useEffect, useCallback } from 'react';
import type { SecurityAlertStats } from '../types/alert';
import { getAlertStats } from '../api/alerts';
import { MOCK_STATS } from '../api/mockData';

export function useStats() {
  const [stats, setStats] = useState<SecurityAlertStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchStats = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await getAlertStats();
      setStats(res);
    } catch {
      setStats(MOCK_STATS);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    // Poll stats every 30s
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  return { stats, loading, error, refetch: fetchStats };
}
