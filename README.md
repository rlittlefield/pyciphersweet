# pyciphersweet
Python implementation of ciphersweet

This is a very early stage implementation of ciphersweet from https://github.com/paragonie/ciphersweet
Please do not attempt to use this in production yet, as I'm not sure if everything works. There are tests that match the original ciphersweet tests and those tests are currently passing.

Currently, only the "modern" modes are supported.

Here is an example of how to create an encrypted field of the last four digits of a number:

    import ciphersweet
    import secrets
    
    nacl_key = secrets.token_bytes(32)
    field = ciphersweet.EncryptedField(
        base_key=nacl_key,
        table='contacts',
        field='ssn',
    )
    t = ciphersweet.Transformation.last_four_digits
    field.add_blind_index('contact_ssn_last_four', t, output_length=16, fast=True)
    index = field.get_blind_index('hello', name='contact_ssn_last_four')
    
    print(index['value'])
    
For documentation on how this works, look into the original ciphersweet project.

