export type TResponseCodesItems = {
  grpcCode: string
  grpcNumber: string
  httpCode: string
  description: string | React.JSX.Element
}

export type TResponseCodes = Record<string, TResponseCodesItems>

export type TVersionedResponseCodes = Record<string, TResponseCodes>
