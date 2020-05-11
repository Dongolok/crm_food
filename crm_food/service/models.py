from django.db import models
from registration.models import Users


class Departments(models.Model):
    name = models.CharField(max_length=120)

    def __str__(self):
        return self.name


class MealCategories(models.Model):
    name = models.CharField(max_length=120)
    department = models.ForeignKey(Departments, on_delete=models.CASCADE)

    def __str__(self):
        return self.name


class Meals(models.Model):
    name = models.CharField(max_length=120)
    category = models.ForeignKey(MealCategories, on_delete=models.CASCADE)
    price = models.CharField(max_length=10)
    description = models.TextField(null=True, default='Some description', max_length=120)

    def __str__(self):
        return self.name


class ServicePercentage(models.Model):
    percentage = models.IntegerField()


class Tables(models.Model):
    name = models.CharField(max_length=120)

    def __str__(self):
        return self.name


class Status(models.Model):
    isitready = models.CharField(max_length=20)

    def __str__(self):
        return '%s' % self.isitready


class Orders(models.Model):
    client = models.CharField(max_length=120)
    user = models.ForeignKey(Users, on_delete=models.CASCADE, default=4 )
    status = models.ForeignKey(Status, on_delete=models.CASCADE, default=1)
    table = models.ForeignKey(Tables, on_delete=models.CASCADE)
    date = models.DateTimeField(auto_now_add=True, null=True)
    isitopen = models.BooleanField(default=False)


class MealsToOrder(models.Model):
    orders = models.ForeignKey(Orders, on_delete=models.CASCADE, related_name='orders_to_make', default=1)
    count = models.IntegerField()
    meals = models.ForeignKey(Meals, on_delete=models.CASCADE, related_name='order_meals', default=1)

    def __str__(self):
        return '%s' % self.orders

    # def save(self, *args, **kwargs):
    #         counting = 0
    #         self.count = int(counting)
    #         super(MealsToOrder, self).save(*args, **kwargs)

    # def sum(self):
    #     count = self.count
    #     meal_id = self.meals
    #     in_sum = MealsToOrder.objects.filter(meals=meal_id)
    #     # return count * sum(in_sum)
    #
    #     return sum(item.get_count() for item in MealsToOrder.objects.filter(meals=meal_id))


class Check(models.Model):
    percentage = models.OneToOneField(ServicePercentage, on_delete=models.CASCADE, default=15, related_name='percentage_check')
    order = models.OneToOneField(Orders, on_delete=models.CASCADE, default=1, related_name='orders_made')
    date = models.DateTimeField(auto_now_add=True, null=True)

    # def total_sum(self):
    #     percentage = self.percentage
    #     regular_sum = MealsToOrder.sum(self)
    #     return int(percentage) * regular_sum + regular_sum
