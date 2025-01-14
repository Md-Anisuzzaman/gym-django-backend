from powerGym_app.model.trainerActivityModel import TrainerActivityModel
from powerGym_app.serializer.trainerActivitySerializer import TranierActivitySerializer
from rest_framework import generics


class TrainerActivityLists(generics.ListCreateAPIView):
    queryset = TrainerActivityModel.objects.all()
    serializer_class = TranierActivitySerializer


class TrainerActivityDetails(generics.RetrieveUpdateDestroyAPIView):
    queryset = TrainerActivityModel.objects.all()
    serializer_class = TranierActivitySerializer