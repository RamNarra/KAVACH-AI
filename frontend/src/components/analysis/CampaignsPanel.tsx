'use client';
import React, { useEffect, useRef, useState } from 'react';
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  CircularProgress,
  Divider,
} from '@mui/material';
import {
  Language as C2Icon,
  Hub as CampaignsIcon,
  Public as GeoIcon,
  Warning as AbuseIcon,
  Storage as ServerIcon,
} from '@mui/icons-material';
import * as d3 from 'd3';
import { getClustering } from '@/lib/api';
import GlassCard from '@/components/ui/GlassCard';

interface CampaignsPanelProps {
  analysisId: string;
}

interface GraphNode extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  type: 'current_apk' | 'c2_server' | 'connected_apk';
  verdict?: string;
  indicator_type?: string;
  geolocation?: string;
  asn?: string;
  reputation?: number;
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  source: string | GraphNode;
  target: string | GraphNode;
  type: string;
}

export default function CampaignsPanel({ analysisId }: CampaignsPanelProps) {
  const [loading, setLoading] = useState<boolean>(true);
  const [data, setData] = useState<{ graph: any; correlations: any[] } | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    let active = true;
    getClustering(analysisId)
      .then((res) => {
        if (active) {
          setData(res as any);
          setLoading(false);
        }
      })
      .catch((err) => {
        console.error('Failed to load clustering data', err);
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [analysisId]);

  useEffect(() => {
    if (!data || !data.graph || !data.graph.nodes || data.graph.nodes.length === 0 || !svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = svgRef.current.clientWidth || 500;
    const height = 300;

    // Deep copy nodes/links to avoid mutating original state in D3 simulation
    const nodes: GraphNode[] = data.graph.nodes.map((n: any) => ({ ...n }));
    const links: GraphLink[] = data.graph.links.map((l: any) => ({ ...l }));

    const simulation = d3.forceSimulation<GraphNode>(nodes)
      .force('link', d3.forceLink<GraphNode, GraphLink>(links).id((d) => d.id).distance(80))
      .force('charge', d3.forceManyBody().strength(-120))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(25));

    // Links
    const link = svg.append('g')
      .selectAll('line')
      .data(links)
      .enter()
      .append('line')
      .attr('stroke', 'rgba(255,255,255,0.12)')
      .attr('stroke-width', 2)
      .attr('stroke-dasharray', (d: any) => d.type === 'shares_infrastructure' ? '4 4' : 'none');

    // Nodes container
    const node = svg.append('g')
      .selectAll('.node')
      .data(nodes)
      .enter()
      .append('g')
      .attr('class', 'node')
      .call(d3.drag<SVGGElement, GraphNode>()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended) as any
      );

    // Node circles
    node.append('circle')
      .attr('r', (d) => d.type === 'current_apk' ? 14 : d.type === 'c2_server' ? 10 : 8)
      .attr('fill', (d) => {
        if (d.type === 'current_apk') return '#6366f1'; // Indigo
        if (d.type === 'c2_server') return '#ef4444'; // Red C2
        return '#f59e0b'; // Amber connected APKs
      })
      .attr('stroke', '#0f172a')
      .attr('stroke-width', 2);

    // Node text labels
    node.append('text')
      .text((d) => {
        const lbl = d.label || '';
        return lbl.length > 18 ? lbl.substring(0, 15) + '...' : lbl;
      })
      .attr('dx', 15)
      .attr('dy', 4)
      .attr('fill', '#e2e8f0')
      .attr('font-size', '9px')
      .attr('font-family', '"Space Grotesk", sans-serif')
      .attr('pointer-events', 'none');

    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      node.attr('transform', (d: any) => `translate(${d.x},${d.y})`);
    });

    function dragstarted(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event: any, d: any) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    return () => {
      simulation.stop();
    };
  }, [data]);

  if (loading) {
    return (
      <GlassCard sx={{ p: 6, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
        <Box sx={{ textAlign: 'center' }}>
          <CircularProgress size={36} sx={{ mb: 2 }} />
          <Typography variant="body2" color="text.secondary">
            Fetching threat intelligence graphs & campaign correlations...
          </Typography>
        </Box>
      </GlassCard>
    );
  }

  const c2Servers = data?.graph?.nodes?.filter((n: any) => n.type === 'c2_server') || [];
  const correlations = data?.correlations || [];

  return (
    <GlassCard>
      {/* Header */}
      <Box
        sx={{
          p: 3,
          borderBottom: '1px solid rgba(99,102,241,0.15)',
          background: 'rgba(99,102,241,0.03)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <Box>
          <Typography variant="h6" sx={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <CampaignsIcon sx={{ color: 'primary.main' }} /> Campaigns & Threat Intel
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Infrastructure mapping & C2 cluster analysis
          </Typography>
        </Box>
        <Chip
          label={`${c2Servers.length} C2 Endpoints`}
          color={c2Servers.length > 0 ? 'error' : 'success'}
          size="small"
        />
      </Box>

      <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', gap: 4 }}>
        {/* Network Graph Visualizer */}
        {c2Servers.length > 0 && (
          <Box>
            <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
              <CampaignsIcon sx={{ fontSize: '1.1rem' }} /> Infrastructure Correlation Map
            </Typography>
            <Paper
              sx={{
                background: 'rgba(10,10,15,0.7)',
                border: '1px solid rgba(255,255,255,0.06)',
                borderRadius: 3,
                p: 1.5,
                position: 'relative',
              }}
            >
              <svg ref={svgRef} style={{ width: '100%', height: 300 }} />
              {/* Legend overlay */}
              <Box
                sx={{
                  position: 'absolute',
                  bottom: 12,
                  left: 12,
                  display: 'flex',
                  gap: 1.5,
                  background: 'rgba(0,0,0,0.6)',
                  px: 1.5,
                  py: 0.7,
                  borderRadius: 2,
                  border: '1px solid rgba(255,255,255,0.08)',
                  flexWrap: 'wrap',
                }}
              >
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: '#6366f1' }} />
                  <Typography variant="caption" sx={{ fontSize: '0.68rem', color: 'text.secondary' }}>Target APK</Typography>
                </Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: '#ef4444' }} />
                  <Typography variant="caption" sx={{ fontSize: '0.68rem', color: 'text.secondary' }}>C2 Server</Typography>
                </Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: '#f59e0b' }} />
                  <Typography variant="caption" sx={{ fontSize: '0.68rem', color: 'text.secondary' }}>Shared Campaign Samples</Typography>
                </Box>
              </Box>
            </Paper>
          </Box>
        )}

        {/* C2 Servers Table */}
        <Box>
          <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <C2Icon sx={{ fontSize: '1.1rem' }} /> Extracted Command & Control (C2) Servers
          </Typography>
          {c2Servers.length > 0 ? (
            <TableContainer component={Paper} sx={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.06)' }}>
              <Table size="small">
                <TableHead sx={{ bgcolor: 'rgba(255,255,255,0.02)' }}>
                  <TableRow>
                    <TableCell><Typography sx={{ fontSize: '0.78rem', fontWeight: 600, color: 'text.secondary' }}>Host / C2 Endpoint</Typography></TableCell>
                    <TableCell><Typography sx={{ fontSize: '0.78rem', fontWeight: 600, color: 'text.secondary' }}>Indicator Type</Typography></TableCell>
                    <TableCell><Typography sx={{ fontSize: '0.78rem', fontWeight: 600, color: 'text.secondary' }}>Geolocation</Typography></TableCell>
                    <TableCell><Typography sx={{ fontSize: '0.78rem', fontWeight: 600, color: 'text.secondary' }}>ASN / ISP</Typography></TableCell>
                    <TableCell align="right"><Typography sx={{ fontSize: '0.78rem', fontWeight: 600, color: 'text.secondary' }}>Abuse Score</Typography></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {c2Servers.map((srv: any) => (
                    <TableRow key={srv.id} sx={{ '&:last-child td, &:last-child th': { border: 0 } }}>
                      <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.78rem', fontWeight: 600, color: '#fca5a5' }}>
                        {srv.label}
                      </TableCell>
                      <TableCell>
                        <Chip label={srv.indicator_type || 'domain'} size="small" variant="outlined" sx={{ fontSize: '0.68rem', height: 18 }} />
                      </TableCell>
                      <TableCell sx={{ fontSize: '0.78rem', color: 'text.secondary' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <GeoIcon sx={{ fontSize: '0.9rem', color: 'primary.light' }} /> {srv.geolocation || 'Unknown Country'}
                        </Box>
                      </TableCell>
                      <TableCell sx={{ fontSize: '0.78rem', color: 'text.secondary' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <ServerIcon sx={{ fontSize: '0.9rem', color: 'text.disabled' }} /> {srv.asn || 'AS-UNKNOWN'}
                        </Box>
                      </TableCell>
                      <TableCell align="right">
                        {srv.reputation !== undefined ? (
                          <Chip
                            label={`${srv.reputation}%`}
                            color={srv.reputation >= 70 ? 'error' : srv.reputation >= 30 ? 'warning' : 'success'}
                            size="small"
                            sx={{ fontWeight: 700, fontSize: '0.68rem', height: 18 }}
                          />
                        ) : (
                          <Typography variant="caption" color="text.disabled">N/A</Typography>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Paper sx={{ p: 3, textAlign: 'center', background: 'rgba(0,0,0,0.1)' }}>
              <Typography variant="body2" color="text.secondary">
                No active C2 servers or dynamic remote endpoints identified.
              </Typography>
            </Paper>
          )}
        </Box>

        {/* Cross Scan Correlations Table */}
        <Box>
          <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
            <AbuseIcon sx={{ fontSize: '1.1rem' }} /> Cross-Scan Campaign Correlations
          </Typography>
          {correlations.length > 0 ? (
            <TableContainer component={Paper} sx={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.06)' }}>
              <Table size="small">
                <TableHead sx={{ bgcolor: 'rgba(255,255,255,0.02)' }}>
                  <TableRow>
                    <TableCell><Typography sx={{ fontSize: '0.78rem', fontWeight: 600, color: 'text.secondary' }}>Correlated File</Typography></TableCell>
                    <TableCell><Typography sx={{ fontSize: '0.78rem', fontWeight: 600, color: 'text.secondary' }}>Shared Indicator</Typography></TableCell>
                    <TableCell><Typography sx={{ fontSize: '0.78rem', fontWeight: 600, color: 'text.secondary' }}>Indicator Type</Typography></TableCell>
                    <TableCell><Typography sx={{ fontSize: '0.78rem', fontWeight: 600, color: 'text.secondary' }}>Verdict</Typography></TableCell>
                    <TableCell align="right"><Typography sx={{ fontSize: '0.78rem', fontWeight: 600, color: 'text.secondary' }}>Reputation</Typography></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {correlations.map((corr: any, idx) => (
                    <TableRow key={`${corr.scan_id}-${idx}`} sx={{ '&:last-child td, &:last-child th': { border: 0 } }}>
                      <TableCell sx={{ fontSize: '0.78rem', fontWeight: 600, color: 'text.primary' }}>
                        {corr.filename}
                      </TableCell>
                      <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.78rem', color: 'text.secondary' }}>
                        {corr.indicator}
                      </TableCell>
                      <TableCell>
                        <Chip label={corr.type} size="small" variant="outlined" sx={{ fontSize: '0.68rem', height: 18 }} />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={corr.verdict}
                          color={corr.verdict === 'MALICIOUS' ? 'error' : 'warning'}
                          size="small"
                          sx={{ fontSize: '0.68rem', height: 18, fontWeight: 600 }}
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Typography sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.78rem', color: 'error.main', fontWeight: 700 }}>
                          {corr.reputation}%
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Paper sx={{ p: 3, textAlign: 'center', background: 'rgba(0,0,0,0.1)' }}>
              <Typography variant="body2" color="text.secondary">
                No threat campaigns or other samples sharing this infrastructure were found. This sample stands isolated.
              </Typography>
            </Paper>
          )}
        </Box>
      </Box>
    </GlassCard>
  );
}
