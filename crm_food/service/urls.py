from .views import *
from django.urls import path

app_name = 'serivce'

urlpatterns = [
    path('departments/', DepartmentsList.as_view()),
    path('departments/<int:pk>', DepartmentsById.as_view()),
    path('mealcategories/', MealCategoriesList.as_view()),
    path('mealcategories/<int:pk>', MealCategoriesBYId.as_view()),
    path('meals/', MealsList.as_view()),
    path('meals/<int:pk>', MealsById.as_view()),
    path('servicefee/', ServicePercentageList.as_view()),
    path('servicefee/<int:pk>', ServicePercentageById.as_view()),
    path('tables/', TablesList.as_view()),
    path('tables/<int:pk>', TablesById.as_view()),
    path('status/', StatusList.as_view()),
    path('status/<int:pk>', StatusById.as_view()),
    path('orders/', OrdersList.as_view()),
    path('orders/<int:pk>', OrdersById.as_view()),
    path('mealstoorder/', MealsToOrderList.as_view()),
    path('mealstoorder/<int:pk>', MealsToOrderById.as_view()),
    path('check/', CheckList.as_view()),
    path('check/<int:pk>', CheckById.as_view())

]
