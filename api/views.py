# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import RSAKeyPair
from .serializers import RSAKeyPairSerializer
from .rsa_signature import generate_rsa_key_pair, sign_file, verify_signature

class RSAKeyPairView(APIView):
    queryset = RSAKeyPair.objects.all()
    serializer_class = RSAKeyPairSerializer

    def get_object(self, pk):
        try:
            return RSAKeyPair.objects.get(pk=pk)
        except RSAKeyPair.DoesNotExist:
            raise Http404

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
        instance = self.get_object(pk)
        instance.delete()
        return Response({'message': 'RSA key pair deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
class SignFileView(APIView):
    queryset = RSAKeyPair.objects.all()
    serializer_class = RSAKeyPairSerializer

    def post(self, request, *args, **kwargs):
        password = request.data.get('password')
        instance = self.get_object()
        file_to_sign = request.FILES['file_to_sign']

        # Verificar la contraseña antes de proceder
        if instance.password == password:
            sign_file(file_to_sign, instance.private_key, password)
            return Response({'message': 'File signed successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)

class VerifySignatureView(APIView):
    queryset = RSAKeyPair.objects.all()
    serializer_class = RSAKeyPairSerializer

    def get(self, request, *args, **kwargs):
        instance = self.get_object()
        original_file = request.FILES['original_file']
        signature_file = request.FILES['signature_file']

        # Verificar la firma
        is_valid = verify_signature(original_file, signature_file, instance.public_key)

        if is_valid:
            return Response({'message': 'Signature is valid'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid signature'}, status=status.HTTP_401_UNAUTHORIZED)
