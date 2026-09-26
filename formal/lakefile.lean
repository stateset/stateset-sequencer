import Lake
open Lake DSL

package sequencerFormal where

@[default_target]
lean_lib Sequencer where
  srcDir := "lean"

@[default_target]
lean_lib ReceiptEncoding where
  srcDir := "lean"

@[default_target]
lean_lib WalRecovery where
  srcDir := "lean"
