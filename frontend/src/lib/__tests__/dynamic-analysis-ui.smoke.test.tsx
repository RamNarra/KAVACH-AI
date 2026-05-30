import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

afterEach(() => {
  cleanup();
});
import { olderCompletedShellDoc, recentCompletedFullDoc } from '../dynamic-analysis-fixtures';
import { DynamicAnalysisOperatorSmokeView } from '../dynamic-analysis-ui';

describe('DynamicAnalysisOperatorSmokeView', () => {
  it('renders full dynamic-analysis state for a recent completed document', () => {
    render(<DynamicAnalysisOperatorSmokeView activeResult={recentCompletedFullDoc} />);

    expect(screen.getByTestId('dynamic-analysis-operator-view')).toBeInTheDocument();
    expect(screen.getByText(/Sandbox: COMPLETED/i)).toBeInTheDocument();
    expect(screen.getByText(/Confidence: full/i)).toBeInTheDocument();

    expect(screen.queryByTestId('partial-analysis-notice')).not.toBeInTheDocument();
    expect(screen.queryByText('No Dynamic Analysis Payload')).not.toBeInTheDocument();
    expect(screen.queryByText('Dynamic Evidence Unavailable')).not.toBeInTheDocument();

    expect(screen.getByTestId('runtime-findings-populated')).toBeInTheDocument();
    expect(screen.getByText('Cleartext HTTP observed')).toBeInTheDocument();
    expect(screen.getByText(/Live Telemetry Intercepts/i)).toBeInTheDocument();
    expect(screen.getByText(/Trigger Playbook Timeline/i)).toBeInTheDocument();
    expect(screen.queryByTestId('runtime-findings-empty')).not.toBeInTheDocument();
  });

  it('renders unavailable dynamic state for an older shell completed document', () => {
    render(<DynamicAnalysisOperatorSmokeView activeResult={olderCompletedShellDoc} />);

    expect(screen.getByText(/Sandbox: UNAVAILABLE/i)).toBeInTheDocument();
    expect(screen.getByText(/Confidence: UNAVAILABLE/i)).toBeInTheDocument();

    expect(screen.getByTestId('partial-analysis-notice')).toBeInTheDocument();
    expect(screen.getByText('Dynamic Evidence Unavailable')).toBeInTheDocument();
    expect(screen.getByText(/not a scan failure/i)).toBeInTheDocument();

    expect(screen.getByTestId('runtime-findings-empty')).toBeInTheDocument();
    expect(screen.getByText(/No clustered runtime findings were recorded/i)).toBeInTheDocument();
    expect(screen.queryByTestId('runtime-findings-populated')).not.toBeInTheDocument();
    expect(screen.queryByText(/Live Telemetry Intercepts/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Analysis Failed/i)).not.toBeInTheDocument();
  });
});
