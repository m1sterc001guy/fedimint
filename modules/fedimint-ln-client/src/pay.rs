use fedimint_core::encoding::{Decodable, Encodable};

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that requests the lightning gateway to pay an invoice on
/// behalf of a federation client.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     CreatedOutgoingLnContract -- await transaction timeout --> Aborted
///     CreatedOutgoingLnContract -- await transaction acceptance --> Funded    
///     Funded -- await gateway pay  --> Success
///     Funded -- tell gateway about contract --> Funded
///     Funded -- timeout --> Refund
///     Funded -- gateway issued refunded --> Refund
///     Refund -- await transaction acceptance --> Refunded
///     Refund -- await transaction rejected --> Failure
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum LnPayStates {}
