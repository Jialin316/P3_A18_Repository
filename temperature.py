from microbit import *


class Temp:
    TEMPERATURE_MAX = 20
    TEMPERATURE_MIN = 16

    def get_temperature(self):
        return temperature()

    def is_alert(self):
        return self.get_temperature() >= self.TEMPERATURE_MAX or self.get_temperature() <= self.TEMPERATURE_MIN
