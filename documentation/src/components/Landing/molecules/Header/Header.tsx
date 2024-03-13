import React, { FC } from 'react'
import styles from './styles.module.css'

export const Header: FC = () => (
  <div className={styles.container}>
    <div className={styles.text}>
      <h1>Documentation that simply works</h1>
      <p>
        Write your documentation in Markdown and create a professional static site in minutes – searchable,
        customizable, in 60+ languages, for all devices.
      </p>
      <a href="/swarm_doc/">
        <button className={styles.button} type="button">
          Get started
        </button>
      </a>
    </div>
  </div>
)
