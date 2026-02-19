import React from 'react';
import { ShieldCheck } from 'lucide-react';
import { useLanguage } from './LanguageContext';

interface TourWelcomeModalProps {
  show: boolean;
  onStartTour: () => void;
  onSkipTour: () => void;
}

const TourWelcomeModal: React.FC<TourWelcomeModalProps> = ({ show, onStartTour, onSkipTour }) => {
  const { t } = useLanguage();

  if (!show) {
    return null;
  }

  return (
    <div className="tour-welcome-overlay" role="dialog" aria-modal="true" aria-label={t('tour.welcome.title')}>
      <div className="tour-welcome-modal">
        <div className="tour-welcome-icon">
          <ShieldCheck size={30} />
        </div>
        <h2>{t('tour.welcome.title')}</h2>
        <p>{t('tour.welcome.body')}</p>
        <div className="tour-welcome-actions">
          <button type="button" className="tour-btn-primary" onClick={onStartTour}>{t('tour.welcome.start')}</button>
          <button type="button" className="tour-btn-secondary" onClick={onSkipTour}>{t('tour.welcome.skip')}</button>
        </div>
      </div>
    </div>
  );
};

export default TourWelcomeModal;
