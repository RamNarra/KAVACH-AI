'use client';
import React, { useEffect, useRef, useState } from 'react';
import {
  Box,
  Typography,
  Chip,
  Paper,
  Divider,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Hub as GraphIcon,
  ZoomIn as ZoomInIcon,
  ZoomOut as ZoomOutIcon,
  FilterCenterFocus as ResetIcon,
  CrisisAlert as SinkIcon,
} from '@mui/icons-material';
import * as d3 from 'd3';
import type { CallGraph, CallGraphNode, CallGraphEdge } from '@/lib/types';
import GlassCard from '@/components/ui/GlassCard';

interface CallGraphPanelProps {
  data?: CallGraph;
}

interface SimNode extends d3.SimulationNodeDatum, CallGraphNode {}
interface SimLink extends d3.SimulationLinkDatum<SimNode> {
  id: string;
  source: string | SimNode;
  target: string | SimNode;
  kind: string;
  risk: string;
}

export default function CallGraphPanel({ data }: CallGraphPanelProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [selectedNode, setSelectedNode] = useState<CallGraphNode | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  useEffect(() => {
    if (!data || !data.nodes || data.nodes.length === 0 || !svgRef.current) return;

    const svgElement = svgRef.current;
    const svg = d3.select(svgElement);
    svg.selectAll('*').remove();

    const width = containerRef.current?.clientWidth || 600;
    const height = 400;

    // Map data to simulation copies
    const nodes: SimNode[] = data.nodes.map((n) => ({ ...n }));
    const links: SimLink[] = data.edges.map((e) => ({
      id: e.id,
      source: e.from,
      target: e.to,
      kind: e.kind,
      risk: e.risk,
    }));

    // Setup zoom
    const zoomGroup = svg.append('g');
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        zoomGroup.attr('transform', event.transform);
      });
    zoomBehaviorRef.current = zoom;
    svg.call(zoom);

    // Setup force simulation
    const simulation = d3.forceSimulation<SimNode>(nodes)
      .force('link', d3.forceLink<SimNode, SimLink>(links).id((d) => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(-150))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(30));

    // Arrow markers for links
    svg.append('defs').append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', 'rgba(255,255,255,0.2)');

    // Render edges/links
    const link = zoomGroup.append('g')
      .selectAll('line')
      .data(links)
      .enter()
      .append('line')
      .attr('stroke', (d) => {
        if (d.risk === 'high-risk') return 'rgba(239, 68, 68, 0.4)';
        return 'rgba(255,255,255,0.1)';
      })
      .attr('stroke-width', (d) => d.risk === 'high-risk' ? 2 : 1)
      .attr('marker-end', 'url(#arrow)');

    // Render node groups
    const node = zoomGroup.append('g')
      .selectAll('.node')
      .data(nodes)
      .enter()
      .append('g')
      .attr('class', 'node')
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        setSelectedNode(d);
        // Highlight clicked node
        node.selectAll('circle').attr('stroke', '#0f172a').attr('stroke-width', 2);
        d3.select(event.currentTarget).select('circle')
          .attr('stroke', '#8b5cf6')
          .attr('stroke-width', 3);
      })
      .call(d3.drag<SVGGElement, SimNode>()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended) as any
      );

    // Node glyphs
    node.append('circle')
      .attr('r', (d) => d.risk === 'malicious' ? 12 : d.risk === 'high-risk' ? 10 : 8)
      .attr('fill', (d) => {
        if (d.risk === 'malicious') return '#ef4444'; // Red
        if (d.risk === 'high-risk') return '#f59e0b'; // Amber
        if (d.type === 'entrypoint') return '#10b981'; // Green
        return '#64748b'; // Slate gray
      })
      .attr('stroke', '#0f172a')
      .attr('stroke-width', 2);

    // Labels
    node.append('text')
      .text((d) => d.label)
      .attr('dx', 14)
      .attr('dy', 4)
      .attr('fill', '#cbd5e1')
      .attr('font-size', '8px')
      .attr('font-family', '"JetBrains Mono", monospace')
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

    // Centered layout fit
    const initialZoom = d3.zoomIdentity.translate(0, 0).scale(0.85);
    svg.call(zoom.transform, initialZoom);

    return () => {
      simulation.stop();
    };
  }, [data]);

  const handleZoom = (factor: number) => {
    if (svgRef.current && zoomBehaviorRef.current) {
      const svg = d3.select(svgRef.current);
      svg.transition().duration(250).call(zoomBehaviorRef.current.scaleBy, factor);
    }
  };

  const handleReset = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      const svg = d3.select(svgRef.current);
      const initialZoom = d3.zoomIdentity.translate(0, 0).scale(0.85);
      svg.transition().duration(250).call(zoomBehaviorRef.current.transform, initialZoom);
    }
  };

  if (!data || !data.nodes || data.nodes.length === 0) {
    return (
      <GlassCard sx={{ p: 4, textAlign: 'center' }}>
        <GraphIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2, opacity: 0.5 }} />
        <Typography variant="body2" color="text.secondary">
          No bytecode call graph available for this sample.
        </Typography>
      </GlassCard>
    );
  }

  const riskyNodes = data.nodes.filter((n) => n.risk === 'malicious' || n.risk === 'high-risk');

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
            <GraphIcon sx={{ color: 'primary.main' }} /> Behavioral Call Graph
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Visualizing API sources, sinks, and execution flows
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Chip
            label={`${data.nodes.length} Nodes`}
            size="small"
            variant="outlined"
          />
          <Chip
            label={`${data.edges.length} Edges`}
            size="small"
            variant="outlined"
          />
        </Box>
      </Box>

      {/* Main Grid View */}
      <Box sx={{ display: 'flex', flexDirection: { xs: 'column', lg: 'row' }, minHeight: 450 }}>
        {/* Left Side: D3 Interactive Graph Area */}
        <Box
          ref={containerRef}
          sx={{
            flexGrow: 1,
            position: 'relative',
            background: 'rgba(10,10,15,0.7)',
            borderRight: { xs: 'none', lg: '1px solid rgba(255,255,255,0.08)' },
            borderBottom: { xs: '1px solid rgba(255,255,255,0.08)', lg: 'none' },
            height: 400,
          }}
        >
          <svg ref={svgRef} style={{ width: '100%', height: '100%' }} />

          {/* Floating Controls */}
          <Box
            sx={{
              position: 'absolute',
              top: 12,
              right: 12,
              display: 'flex',
              flexDirection: 'column',
              gap: 0.5,
              background: 'rgba(0,0,0,0.6)',
              p: 0.5,
              borderRadius: 2,
              border: '1px solid rgba(255,255,255,0.08)',
            }}
          >
            <IconButton size="small" onClick={() => handleZoom(1.2)} title="Zoom In"><ZoomInIcon sx={{ fontSize: '1.2rem' }} /></IconButton>
            <IconButton size="small" onClick={() => handleZoom(0.8)} title="Zoom Out"><ZoomOutIcon sx={{ fontSize: '1.2rem' }} /></IconButton>
            <IconButton size="small" onClick={handleReset} title="Reset View"><ResetIcon sx={{ fontSize: '1.2rem' }} /></IconButton>
          </Box>

          {/* Bottom legend */}
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
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: '#ef4444' }} />
              <Typography variant="caption" sx={{ fontSize: '0.68rem', color: 'text.secondary' }}>Malicious</Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: '#f59e0b' }} />
              <Typography variant="caption" sx={{ fontSize: '0.68rem', color: 'text.secondary' }}>High-Risk</Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: '#10b981' }} />
              <Typography variant="caption" sx={{ fontSize: '0.68rem', color: 'text.secondary' }}>Entrypoint</Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: '#64748b' }} />
              <Typography variant="caption" sx={{ fontSize: '0.68rem', color: 'text.secondary' }}>Benign</Typography>
            </Box>
          </Box>
        </Box>

        {/* Right Side: Sidebar details */}
        <Box
          sx={{
            width: { xs: '100%', lg: 280 },
            p: 3,
            overflowY: 'auto',
            maxHeight: 400,
            display: 'flex',
            flexDirection: 'column',
            gap: 2.5,
            flexShrink: 0,
          }}
        >
          {selectedNode ? (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <Box>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>Selected Method</Typography>
                <Typography sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.82rem', fontWeight: 700, wordBreak: 'break-all' }}>
                  {selectedNode.label}
                </Typography>
              </Box>

              <Divider sx={{ borderColor: 'rgba(255,255,255,0.06)' }} />

              <Box>
                <Typography variant="caption" color="text.secondary">Class Namespace</Typography>
                <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.74rem', color: 'text.secondary', wordBreak: 'break-all' }}>
                  {selectedNode.class}
                </Typography>
              </Box>

              <Box>
                <Typography variant="caption" color="text.secondary">Method Name</Typography>
                <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace', fontSize: '0.74rem', color: 'text.secondary' }}>
                  {selectedNode.method}()
                </Typography>
              </Box>

              <Box>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>Forensic Tag / Type</Typography>
                <Chip
                  label={selectedNode.type.toUpperCase()}
                  color={
                    selectedNode.risk === 'malicious'
                      ? 'error'
                      : selectedNode.risk === 'high-risk'
                      ? 'warning'
                      : 'primary'
                  }
                  size="small"
                  sx={{ fontSize: '0.68rem', height: 18, fontWeight: 700 }}
                />
              </Box>

              {selectedNode.tags && selectedNode.tags.length > 0 && (
                <Box>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>API Category Tags</Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {selectedNode.tags.map((t, idx) => (
                      <Chip key={`${t}-${idx}`} label={t} size="small" variant="outlined" sx={{ fontSize: '0.65rem', height: 16 }} />
                    ))}
                  </Box>
                </Box>
              )}
            </Box>
          ) : (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                High-Risk API Sinks ({riskyNodes.length})
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Click any node in the graph, or pick a high-risk sink below to inspect call parameters.
              </Typography>

              <Paper sx={{ background: 'rgba(0,0,0,0.15)', maxHeight: 220, overflowY: 'auto', border: '1px solid rgba(255,255,255,0.04)' }}>
                <List dense sx={{ p: 0 }}>
                  {riskyNodes.map((n) => (
                    <ListItem
                      key={n.id}
                      onClick={() => setSelectedNode(n)}
                      sx={{
                        cursor: 'pointer',
                        py: 0.8,
                        '&:hover': { background: 'rgba(255,255,255,0.03)' }
                      }}
                    >
                      <Box sx={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', width: '100%' }}>
                        <Typography
                          sx={{
                            fontFamily: '"JetBrains Mono", monospace',
                            fontSize: '0.7rem',
                            fontWeight: 700,
                            color: n.risk === 'malicious' ? 'error.main' : 'warning.main',
                            textOverflow: 'ellipsis',
                            overflow: 'hidden',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {n.label}
                        </Typography>
                        <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary' }}>
                          {n.type}
                        </Typography>
                      </Box>
                    </ListItem>
                  ))}
                  {riskyNodes.length === 0 && (
                    <ListItem sx={{ py: 2 }}>
                      <Typography variant="caption" color="text.disabled" sx={{ textAlign: 'center', width: '100%' }}>
                        No suspicious API sinks found in this DEX graph.
                      </Typography>
                    </ListItem>
                  )}
                </List>
              </Paper>
            </Box>
          )}
        </Box>
      </Box>
    </GlassCard>
  );
}
