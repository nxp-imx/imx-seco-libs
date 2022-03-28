#! /usr/bin/env python3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms

##################################################################
###                                                            ###
###   NOTE: THIS FEATURE IS ONLY SUPPORTED ON IMX8 DXL B0      ###
###                                                            ###
##################################################################


###############  USE OF THIS SCRIPT  ############################################
#
#  1. Fill in customer_otp variable below to correspond to OEM secret
#
#  2. Run this python script
#
#  3. Console will give SECO and V2X KEK to use for open and closed lifecycles
#
#################################################################################



# Customer to fill in securely provisioned OEM closed otp secret with a valid AES 256 key
customer_otp = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

# OEM open always uses facsimile otp secret - do not change this value
facsimile_otp = "693f25bd6a299107cf7220b9ab504111fd3003bfe9aa38294262c3abab372790"


def run_kdf(otp_val, label):

# FIPS compliant key derivation (SP 800-108)
#   - CMAC based KDF in counter mode
#   - two loops of algorithm (256 bits generated)
#   - label set by caller as "SECO HSM" or "V2X HSM"
#   - context is "NXP IMX8 DXL B0 OTP ROOT KEK"

    label_hex = label.encode("utf_8").hex()

    zero_byte = "00"

    context = "NXP IMX8 DXL B0 OTP ROOT KEK"
    context_hex = context.encode("utf_8").hex()

    L = "0100"  # 256 bits = 0x100

    fixed_info = label_hex + zero_byte + context_hex + L

    # First loop
    counter = "00000001"
    kdf_input = counter + fixed_info

    cmac = CMAC(algorithms.AES(bytes.fromhex(otp_val)), default_backend())
    cmac.update(bytes.fromhex(kdf_input))
    key_val = cmac.finalize()

    # Second loop
    counter = "00000002"
    kdf_input = counter + fixed_info

    cmac = CMAC(algorithms.AES(bytes.fromhex(otp_val)), default_backend())
    cmac.update(bytes.fromhex(kdf_input))
    key_val += cmac.finalize()

    print(key_val.hex())

def calc_seco_key(otp_val):
    run_kdf(otp_val, "SECO HSM")

def calc_v2x_key(otp_val):
    run_kdf(otp_val, "V2X HSM")


if __name__ == "__main__":
    print("OEM closed SECO KEK:")
    calc_seco_key(customer_otp)
    print("OEM closed V2X KEK:")
    calc_v2x_key(customer_otp)
    print("OEM open SECO KEK:")
    calc_seco_key(facsimile_otp)
    print("OEM open V2X KEK:")
    calc_v2x_key(facsimile_otp)

