import React, { FC } from 'react'
import styles from './styles.module.css'

export const LandingFeatures: FC = () => (
  <div className={styles.container}>
    <h1>Everything you would expect</h1>
    <div className={styles.grid}>
      <div>
        <h2>It`s just Markdown</h2>
        <p>
          Focus on the content of your documentation and create a professional static site in minutes. No need to know
          HTML, CSS or JavaScript – let Material for MkDocs do the heavy lifting for you.
        </p>
      </div>
      <div>
        <h2>Works on all devices</h2>
        <p>
          Serve your documentation with confidence – Material for MkDocs automatically adapts to perfectly fit the
          available screen estate, no matter the type or size of the viewing device. Desktop. Tablet. Mobile. All great.
        </p>
      </div>
      <div>
        <h2>Made to measure</h2>
        <p>
          Make it yours – change the colors, fonts, language, icons, logo, and more with a few lines of configuration.
          Material for MkDocs can be easily extended and provides many options to alter appearance and behavior.
        </p>
      </div>
      <div>
        <h2>Fast and lightweight</h2>
        <p>
          Don`t let your users wait – get incredible value with a small footprint by using one of the fastest themes
          available with excellent performance, yielding optimal search engine rankings and happy users that return.
        </p>
      </div>
      <div>
        <h2>Maintain ownership</h2>
        <p>
          Own your documentation`s complete sources and outputs, guaranteeing both integrity and security – no need to
          entrust the backbone of your product knowledge to third-party platforms. Retain full control.
        </p>
      </div>
      <div>
        <h2>Open Source</h2>
        <p>
          You`re in good company – choose a mature and actively maintained solution built with state-of-the-art Open
          Source technologies, trusted by more than 20.000 individuals and organizations. Licensed under MIT.
        </p>
      </div>
    </div>
  </div>
)
