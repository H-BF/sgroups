import React, { FC } from 'react'
import styles from './styles.module.css'

export const Header: FC = () => (
  <div className={styles.container}>
    <div className={styles.text}>
      <h1>Firewall that simply works</h1>
      <p>
      Create secure networks in your company in a matter of minutes using network 
      microsegmentation based on S.Groups!".
      </p>
      <a href="/sgroups/">
        <button className={styles.button} type="button">
          Get started
        </button>
      </a>
    </div>
  </div>
)
