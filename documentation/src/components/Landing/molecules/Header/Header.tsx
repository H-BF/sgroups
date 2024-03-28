import React, { FC } from 'react'
import styles from './styles.module.css'

export const Header: FC = () => (
  <div className={styles.container}>
    <div className={styles.text}>
      <h1>Firewall, который работает</h1>
      <p>
        Создавайте защищенные сети в вашей организации за пару минут, используя сетевую микросегментацию, основанную на
        S.Groups
      </p>
      <a href="/sgroups/info/introduction/">
        <button className={styles.button} type="button">
          Начать
        </button>
      </a>
    </div>
  </div>
)
