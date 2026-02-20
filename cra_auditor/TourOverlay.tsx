import React, { useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import { TOUR_STEPS, TourPlacement, useTour } from './TourContext';
import { useLanguage } from './LanguageContext';

interface Rectangle {
  top: number;
  left: number;
  width: number;
  height: number;
}

interface TooltipLayout {
  placement: TourPlacement;
  style: React.CSSProperties;
}

const TOOLTIP_WIDTH = 340;
const TOOLTIP_MARGIN = 16;
const SPOTLIGHT_PADDING = 10;

/** Clamp numeric value to a min/max interval. */
const clamp = (value: number, minValue: number, maxValue: number): number => {
  return Math.min(Math.max(value, minValue), maxValue);
};

/** Replace {placeholders} in translated strings with runtime values. */
const interpolate = (template: string, values: Record<string, string | number>): string => {
  return template.replace(/\{(\w+)\}/g, (_, key: string) => String(values[key] ?? ''));
};

/** Fallback spotlight rectangle when the target element cannot be resolved. */
const fallbackRect = (): Rectangle => {
  const top = window.innerHeight * 0.32;
  const left = window.innerWidth * 0.25;
  const width = window.innerWidth * 0.5;
  const height = 88;

  return { top, left, width, height };
};

/** Compute tooltip position around the highlighted target area. */
const resolveTooltipPosition = (targetRect: Rectangle, placement: TourPlacement): TooltipLayout => {
  const tooltipHeightGuess = 220;
  const tooltipWidth = Math.min(TOOLTIP_WIDTH, window.innerWidth - TOOLTIP_MARGIN * 2);
  const maxLeft = Math.max(window.innerWidth - tooltipWidth - TOOLTIP_MARGIN, TOOLTIP_MARGIN);
  const maxTop = Math.max(window.innerHeight - tooltipHeightGuess - TOOLTIP_MARGIN, TOOLTIP_MARGIN);

  const placementCandidates: Record<TourPlacement, TourPlacement[]> = {
    top: ['top', 'bottom', 'right', 'left'],
    bottom: ['bottom', 'top', 'right', 'left'],
    left: ['left', 'right', 'bottom', 'top'],
    right: ['right', 'left', 'bottom', 'top']
  };

  const computePosition = (candidate: TourPlacement): React.CSSProperties => {
    if (candidate === 'top') {
      return {
        left: clamp(targetRect.left + targetRect.width / 2 - tooltipWidth / 2, TOOLTIP_MARGIN, maxLeft),
        top: clamp(targetRect.top - tooltipHeightGuess - TOOLTIP_MARGIN, TOOLTIP_MARGIN, maxTop)
      };
    }

    if (candidate === 'left') {
      return {
        left: clamp(targetRect.left - tooltipWidth - TOOLTIP_MARGIN, TOOLTIP_MARGIN, maxLeft),
        top: clamp(targetRect.top + targetRect.height / 2 - tooltipHeightGuess / 2, TOOLTIP_MARGIN, maxTop)
      };
    }

    if (candidate === 'right') {
      return {
        left: clamp(targetRect.left + targetRect.width + TOOLTIP_MARGIN, TOOLTIP_MARGIN, maxLeft),
        top: clamp(targetRect.top + targetRect.height / 2 - tooltipHeightGuess / 2, TOOLTIP_MARGIN, maxTop)
      };
    }

    return {
      left: clamp(targetRect.left + targetRect.width / 2 - tooltipWidth / 2, TOOLTIP_MARGIN, maxLeft),
      top: clamp(targetRect.top + targetRect.height + TOOLTIP_MARGIN, TOOLTIP_MARGIN, maxTop)
    };
  };

  const isOverlapping = (tooltipStyle: React.CSSProperties): boolean => {
    const tooltipTop = Number(tooltipStyle.top ?? 0);
    const tooltipLeft = Number(tooltipStyle.left ?? 0);
    const overlapPadding = 10;
    const targetTop = targetRect.top - overlapPadding;
    const targetLeft = targetRect.left - overlapPadding;
    const targetRight = targetRect.left + targetRect.width + overlapPadding;
    const targetBottom = targetRect.top + targetRect.height + overlapPadding;
    const tooltipRight = tooltipLeft + tooltipWidth;
    const tooltipBottom = tooltipTop + tooltipHeightGuess;

    return tooltipLeft < targetRight
      && tooltipRight > targetLeft
      && tooltipTop < targetBottom
      && tooltipBottom > targetTop;
  };

  for (const candidate of placementCandidates[placement]) {
    const candidateStyle = computePosition(candidate);
    if (!isOverlapping(candidateStyle)) {
      return { placement: candidate, style: candidateStyle };
    }
  }

  return {
    placement,
    style: computePosition(placement)
  };
};

/** Resolve first matching target element from a comma-separated selector list. */
const resolveTargetElement = (selector: string): HTMLElement | null => {
  const selectors = selector
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  for (const selectorEntry of selectors) {
    const matchedElement = document.querySelector(selectorEntry) as HTMLElement | null;
    if (matchedElement) {
      return matchedElement;
    }
  }

  return null;
};

const TourOverlay: React.FC = () => {
  const { t } = useLanguage();
  const { isTourActive, currentStep, nextStep, prevStep, endTour } = useTour();
  const [targetRect, setTargetRect] = useState<Rectangle | null>(null);

  const currentTourStep = TOUR_STEPS[currentStep];

  useEffect(() => {
    if (!isTourActive || !currentTourStep) {
      setTargetRect(null);
      return;
    }

    const updateTargetPosition = (shouldScroll = false) => {
      const element = resolveTargetElement(currentTourStep.targetSelector);

      if (!element) {
        setTargetRect(fallbackRect());
        return;
      }

      if (shouldScroll) {
        element.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
      }
      const rect = element.getBoundingClientRect();
      setTargetRect({
        top: rect.top,
        left: rect.left,
        width: rect.width,
        height: rect.height
      });
    };

    updateTargetPosition(true);

    const animationFrameIds: number[] = [];
    const firstAnimationFrameId = window.requestAnimationFrame(() => {
      updateTargetPosition(false);
      const secondAnimationFrameId = window.requestAnimationFrame(() => updateTargetPosition(false));
      animationFrameIds.push(secondAnimationFrameId);
    });
    animationFrameIds.push(firstAnimationFrameId);
    const intervalId = window.setInterval(() => updateTargetPosition(false), 140);
    const delayedPassId = window.setTimeout(() => updateTargetPosition(false), 420);
    const handleLayoutChange = () => updateTargetPosition(false);

    window.addEventListener('resize', handleLayoutChange);
    window.addEventListener('scroll', handleLayoutChange, true);

    return () => {
      for (const animationFrameId of animationFrameIds) {
        window.cancelAnimationFrame(animationFrameId);
      }
      window.clearInterval(intervalId);
      window.clearTimeout(delayedPassId);
      window.removeEventListener('resize', handleLayoutChange);
      window.removeEventListener('scroll', handleLayoutChange, true);
    };
  }, [isTourActive, currentTourStep]);

  useEffect(() => {
    if (!isTourActive) {
      return;
    }

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        endTour();
      }
    };

    window.addEventListener('keydown', handleEscape);
    return () => window.removeEventListener('keydown', handleEscape);
  }, [isTourActive, endTour]);

  const progressText = useMemo(() => {
    return interpolate(t('tour.progress'), { current: currentStep + 1, total: TOUR_STEPS.length });
  }, [t, currentStep]);

  if (!isTourActive || !currentTourStep || typeof document === 'undefined' || !targetRect) {
    return null;
  }

  const widthAdjust = currentTourStep.spotlightWidthAdjust ?? 0;
  const heightAdjust = currentTourStep.spotlightHeightAdjust ?? 0;
  const adjustedWidth = Math.max(targetRect.width + SPOTLIGHT_PADDING * 2 + widthAdjust, 24);
  const adjustedHeight = Math.max(targetRect.height + SPOTLIGHT_PADDING * 2 + heightAdjust, 24);

  const spotlightRect: Rectangle = {
    top: Math.max(targetRect.top - SPOTLIGHT_PADDING + (currentTourStep.spotlightOffsetY ?? 0), TOOLTIP_MARGIN),
    left: Math.max(targetRect.left - SPOTLIGHT_PADDING + (currentTourStep.spotlightOffsetX ?? 0), TOOLTIP_MARGIN),
    width: Math.min(adjustedWidth, window.innerWidth - TOOLTIP_MARGIN * 2),
    height: Math.min(adjustedHeight, window.innerHeight - TOOLTIP_MARGIN * 2)
  };

  const spotlightStyle: React.CSSProperties = {
    top: spotlightRect.top,
    left: spotlightRect.left,
    width: spotlightRect.width,
    height: spotlightRect.height
  };

  const tooltipLayout = resolveTooltipPosition(spotlightRect, currentTourStep.placement);

  return createPortal(
    <div className="tour-overlay" role="presentation">
      <div className="tour-spotlight" style={spotlightStyle} />
      <div className={`tour-tooltip tour-tooltip-${tooltipLayout.placement}`} style={tooltipLayout.style} role="dialog" aria-live="polite">
        <div className="tour-tooltip-arrow" />
        <div className="tour-progress">{progressText}</div>
        <h3>{t(currentTourStep.titleKey)}</h3>
        <p>{t(currentTourStep.descriptionKey)}</p>
        <div className="tour-tooltip-actions">
          <button type="button" onClick={prevStep} disabled={currentStep === 0}>{t('tour.btn.back')}</button>
          <button type="button" onClick={nextStep}>{t('tour.btn.next')}</button>
          <button type="button" onClick={endTour}>{t('tour.btn.endTour')}</button>
        </div>
      </div>
    </div>,
    document.body
  );
};

export default TourOverlay;
