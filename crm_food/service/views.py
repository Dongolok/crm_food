from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import *
from .serializers import *
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated


class DepartmentsList(generics.ListCreateAPIView):
    permission_classes = (IsAuthenticated,)

    queryset = Departments.objects.all()
    serializer_class = DepartmentsSerializer


class DepartmentsById(generics.RetrieveDestroyAPIView):
    queryset = Departments.objects.all()
    serializer_class = DepartmentsSerializer
    permission_classes = (IsAuthenticated,)


class MealCategoriesList(generics.ListCreateAPIView):
    queryset = MealCategories.objects.all()
    serializer_class = MealCategoriesSerializer
    permission_classes = (IsAuthenticated,)


class MealCategoriesBYId(generics.RetrieveDestroyAPIView):
    queryset = MealCategories.objects.all()
    serializer_class = MealCategoriesSerializer
    permission_classes = (IsAuthenticated,)


class MealsList(generics.ListCreateAPIView):
    queryset = Meals.objects.all()
    serializer_class = MealsSerializer
    permission_classes = (IsAuthenticated,)


class MealsById(generics.RetrieveUpdateDestroyAPIView):
    queryset = Meals.objects.all()
    serializer_class = MealsSerializer
    permission_classes = (IsAuthenticated,)


class ServicePercentageList(generics.ListCreateAPIView):
    queryset = ServicePercentage.objects.all()
    serializer_class = ServicePercentageSerializer
    permission_classes = (IsAuthenticated,)


class ServicePercentageById(generics.RetrieveDestroyAPIView):
    queryset = ServicePercentage.objects.all()
    serializer_class = ServicePercentageSerializer
    permission_classes = (IsAuthenticated,)


class TablesList(generics.ListCreateAPIView):
    queryset = Tables.objects.all()
    serializer_class = TablesSerializer
    permission_classes = (IsAuthenticated,)


class TablesById(generics.RetrieveDestroyAPIView):
    queryset = Tables.objects.all()
    serializer_class = TablesSerializer
    permission_classes = (IsAuthenticated,)


class StatusList(generics.ListCreateAPIView):
    queryset = Status.objects.all()
    serializer_class = StatusSerializer
    permission_classes = (IsAuthenticated,)


class StatusById(generics.RetrieveDestroyAPIView):
    queryset = Status.objects.all()
    serializer_class = StatusSerializer
    permission_classes = (IsAuthenticated,)


class OrdersList(generics.ListCreateAPIView):
    queryset = Orders.objects.all()
    serializer_class = OrdersSerializer
    permission_classes = (IsAuthenticated,)


class OrdersById(generics.RetrieveDestroyAPIView):
    queryset = Orders.objects.all()
    serializer_class = OrdersSerializer
    permission_classes = (IsAuthenticated,)


class MealsToOrderList(generics.ListCreateAPIView):
    queryset = MealsToOrder.objects.all()
    serializer_class = MealsToOrderSerializer
    permission_classes = (IsAuthenticated,)


class MealsToOrderById(generics.RetrieveDestroyAPIView):
    queryset = MealsToOrder.objects.all()
    serializer_class = MealsToOrderSerializer
    permission_classes = (IsAuthenticated,)


class CheckList(generics.ListCreateAPIView):
    queryset = Check.objects.all()
    serializer_class = CheckSerializer
    permission_classes = (IsAuthenticated,)


class CheckById(generics.RetrieveDestroyAPIView):
    queryset = Check.objects.all()
    serializer_class = CheckSerializer
    permission_classes = (IsAuthenticated,)
