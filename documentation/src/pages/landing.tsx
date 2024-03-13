/* eslint-disable import/no-default-export */
import React, { FC } from 'react'
import Layout from '@theme/Layout'
import { Header, LandingFeatures } from '@site/src/components/Landing/molecules'
import styles from './index.module.css'

const LandingPage: FC = () => {
  return (
    <Layout title="SGroups" description="SGroups">
      <Header />
      <div className={styles.container}>
        <LandingFeatures />
      </div>
    </Layout>
  )
}

export default LandingPage
