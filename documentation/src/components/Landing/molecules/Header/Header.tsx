import React, { FC } from 'react'
import styles from './styles.module.css'

export const Header: FC = () => (
  <div className={styles.container}>
    <div className={styles.text}>
      <h1>
      SGroups - Host Based NGFW
      </h1>
      <h2>
      <span>Будущее безопасной сети</span>
      </h2>
      
      <p>
        Создавайте защищенные сети в вашей организации за пару минут, используя весь функционал <span>sgroups</span> для сетевой микросегментации.
      </p>
      <a href="/sgroups/info/introduction/">
        <button className={styles.button} type="button">
          Начать
        </button>
      </a>
    </div>
  </div>
)
