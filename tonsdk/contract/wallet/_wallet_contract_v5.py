import time

from ._wallet_contract import WalletContract
from ...boc import Cell


class WalletV5ContractR1(WalletContract):
    def __init__(self, **kwargs):
        self.code = "te6cckECFAEAAoEAART/APSkE/S88sgLAQIBIAIDAgFIBAUBAvIOAtzQINdJwSCRW49jINcLHyCCEGV4dG69IYIQc2ludL2wkl8D4IIQZXh0brqOtIAg1yEB0HTXIfpAMPpE+Cj6RDBYvZFb4O1E0IEBQdch9AWDB/QOb6ExkTDhgEDXIXB/2zzgMSDXSYECgLmRMOBw4hAPAgEgBgcCASAICQAZvl8PaiaECAoOuQ+gLAIBbgoLAgFIDA0AGa3OdqJoQCDrkOuF/8AAGa8d9qJoQBDrkOuFj8AAF7Ml+1E0HHXIdcLH4AARsmL7UTQ1woAgAR4g1wsfghBzaWduuvLgin8PAeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEAP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKERITAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQAcjDXLAgkji0h8uCS0gDtRNDSAFETuvLQj1RQMJExnAGBAUDXIdcKAPLgjuLIygBYzxbJ7VST8sCN4gAQk1vbMeHXTNCon9ZI"
        kwargs["code"] = Cell.one_from_boc(self.code)
        super().__init__(**kwargs)
        self.workchain = kwargs.get("wc", 0)
        self.network_global_id = kwargs.get(
            "network_global_id", -239
        )  # MainnetGlobalID
        self.wallet_id = self._gen_wallet_id()
        self.is_signature_allowed = True

    def _gen_context_id(self):
        context_cell = Cell()
        context_cell.bits.write_uint(1, 1)
        context_cell.bits.write_int(self.workchain, 8)
        context_cell.bits.write_uint(0, 8)
        context_cell.bits.write_uint(0, 15)
        return context_cell.bits.get_top_upped_array()

    def _gen_wallet_id(self):
        context_id = int.from_bytes(self._gen_context_id(), byteorder="big")
        wallet_id = context_id ^ (self.network_global_id & 0xFFFFFFFF)
        return wallet_id & 0xFFFFFFFF  # Ensure it's a 32-bit unsigned integer

    def create_data_cell(self):
        cell = Cell()
        cell.bits.write_uint(1 if self.is_signature_allowed else 0, 1)
        cell.bits.write_uint(0, 32)  # seqno
        cell.bits.write_uint(self.wallet_id, 32)
        cell.bits.write_bytes(self.options["public_key"])
        cell.bits.write_uint(0, 1)  # Empty dict for extensions
        return cell

    def create_signing_message(self, seqno=None, messages=None):
        seqno = seqno or 0
        wallet_id = self.wallet_id
        valid_until = int(time.time()) + self.options.get("timeout", 60)

        message = Cell()
        message.bits.write_uint(0x7369676E, 32)  # 'sign' magic prefix
        message.bits.write_uint(wallet_id, 32)
        message.bits.write_uint(valid_until, 32)
        message.bits.write_uint(seqno, 32)

        if messages:
            actions = self._pack_actions(messages)
            message.refs.append(actions)

        return message

    def _pack_actions(self, messages):
        actions = Cell()
        actions.bits.write_uint(1, 1)  # Store 1 at the beginning

        prev_cell = None
        for msg in reversed(messages):
            cell = Cell()
            if prev_cell:
                cell.refs.append(prev_cell)

            out_msg = self._create_outbound_message(msg)

            cell.bits.write_uint(0x0EC3C86D, 32)  # action_send_msg prefix
            cell.bits.write_uint(msg.get("mode", 3), 8)  # Mode
            cell.refs.append(out_msg)

            prev_cell = cell

        if prev_cell:
            actions.refs.append(prev_cell)
        actions.bits.write_uint(0, 1)  # Store 0 at the end

        return actions

    def _create_outbound_message(self, msg):
        # This method needs to be implemented based on your specific message structure
        # It should create a Cell object representing the outbound message
        pass

    def get_address(self):
        state_init = self.create_state_init()
        return state_init["address"]