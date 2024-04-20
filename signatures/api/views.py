from signatures.api.serializers import SignaturesSerializer
from rest_framework import viewsets
from signatures.models import Signatures


class SignaturesViewSet(viewsets.ModelViewSet):
    queryset = Signatures.objects.all()
    serializer_class = SignaturesSerializer

    def get_queryset(self):
        return self.queryset


# class EndPointViewSet(viewsets.ModelViewSet):
#     queryset = WayBackEndPoint.objects.all()
#     serializer_class = EndpointSerializer

#     def get_queryset(self):
#         req = self.request
#         url_of = req.query_params.get('url_of')
#         if url_of:
#             self.queryset = WayBackEndPoint.objects.filter(url_of__id=url_of)
#             return self.queryset
#         else:
#             return self.queryset


# class VulnerabilityViewSet(viewsets.ModelViewSet):
#     queryset = VulnerabilityScan.objects.all()
#     serializer_class = VulnerabilitySerializer

#     def get_queryset(self):
#         req = self.request
#         vulnerability_of = req.query_params.get('vulnerability_of')
#         if vulnerability_of:
#             self.queryset = VulnerabilityScan.objects.filter(
#                 vulnerability_of__id=vulnerability_of)
#             return self.queryset
#         else:
#             return self.queryset
