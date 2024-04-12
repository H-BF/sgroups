export type TDefinition = {
  short: string
  full: string
}

export type TDictionary = Record<string, TDefinition>

export type TVersionedDictionary = Record<string, TDictionary>
