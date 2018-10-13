# pyciphersweet
Python implementation of ciphersweet

This is a very early stage implementation of ciphersweet from https://github.com/paragonie/ciphersweet
Please do not attempt to use this in production yet, as I'm not sure if everything works. There are tests that match the original ciphersweet tests and those tests are currently passing.

Currently, only the "modern" modes are supported.

Here is an example of how to create an encrypted field of the last four digits of a number:


    field = ciphersweet.EncryptedField(
        base_key=nacl_key,
        table='contacts',
        field='ssn',
    )
    t = ciphersweet.Transformation.last_four_digits
    field.add_blind_index('contact_ssn_last_four', t, output_length=16, fast=True)


