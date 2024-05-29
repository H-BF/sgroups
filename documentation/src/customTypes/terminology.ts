export type TTerminology = {
  name: string
  comment?: string
  definition: string | React.JSX.Element
  link?: string
}

export type TVersionedTerminology = Record<string, TTerminology[]>
