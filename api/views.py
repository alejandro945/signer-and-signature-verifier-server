# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import RSAKeyPair
from .serializers import RSAKeyPairSerializer
from .rsa_signature import generate_rsa_key_pair, sign_file, verify_signature
from cryptography.exceptions import InvalidKey

class RSAKeyPairView(APIView):
    queryset = RSAKeyPair.objects.all()
    serializer_class = RSAKeyPairSerializer

    def get_object(self, pk):
        return RSAKeyPair.objects.get(pk=pk)

    def get(self, request, *args, **kwargs):
        #Return all RSA key pairs
        keys = RSAKeyPair.objects.all()
        keySerializer = RSAKeyPairSerializer(keys, many=True)
        return Response(keySerializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        password = self.request.data.get('password')
        private_key, public_key = generate_rsa_key_pair(password)
        serializer = self.serializer_class(data={'private_key': private_key, 'public_key': public_key, 'password': password})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    def delete(self, request, pk, format=None):
        try:
            instance = self.get_object(pk)
            instance.delete()
            return Response({'message': 'RSA key pair deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except RSAKeyPair.DoesNotExist:
            return Response({'error': 'RSA key pair does not exist'}, status=status.HTTP_404_NOT_FOUND)
    
class SignFileView(APIView):
    """
    This option receives as inputs any @file_to_sign, and @private_key_file. 
    Once the private key lock password has been verified, the program must 
    generate the digital signature of the file, and save it in a separate file.
    """
    def post(self, request, *args, **kwargs):
        password = request.data.get('password')
        file_to_sign = request.FILES['file_to_sign']
        private_key_file = request.FILES['private_key_file']
        #Extract data from files
        private_key = private_key_file.read()
        file_to_sign = file_to_sign.read()
        try:
            signature = sign_file(file_to_sign, private_key, password)
            return Response({'signature': signature}, status=status.HTTP_201_CREATED)
        except ValueError:
            return Response({'error': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)

"""
This option receives as inputs any @original_file, @signature_file, and @public_key_file.
The program must verify that the signature corresponds to the original file.
"""
class VerifySignatureView(APIView):
    def post(self, request, *args, **kwargs):
        original_file = request.FILES['original_file']
        signature_file = request.FILES['signature_file']
        public_key_file = request.FILES['public_key_file']
        # Verify signature
        try:
            verify_signature(original_file.read(), signature_file.read(), public_key_file.read())
            return Response({'message': 'Signature is valid'}, status=status.HTTP_200_OK)
        except Exception:
            return Response({'error': 'Invalid signature'}, status=status.HTTP_401_UNAUTHORIZED)
