from django.test import TestCase

# Create your tests here.

# Path: signer_and_signature_verifier_server/api/tests.py
# Compare this snippet from signer_and_signature_verifier_server/api/tests.py:
# from django.test import TestCase
# from django.urls import reverse
# from rest_framework import status
# from rest_framework.test import APITestCase
#
# from .models import RSAKeyPair
#
# class RSAKeyPairTests(APITestCase):
#     def test_create_key_pair(self):
#         """
#         Ensure we can create a new RSAKeyPair object.
#         """
#         url = reverse('generate-key-pair')
#         data = {}
#         response = self.client.post(url, data, format='json')
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
#         self.assertEqual(RSAKeyPair.objects.count(), 1)
#         self.assertEqual(RSAKeyPair.objects.get().id, 1)
#
# class SignFileTests(APITestCase):
#     def test_sign_file(self):
#         """
#         Ensure we can sign a file.
#         """
#         url = reverse('sign-file')
#         data = {}
#         response = self.client.post(url, data, format='json')
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
#
