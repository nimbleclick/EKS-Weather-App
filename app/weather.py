from pprint import pprint
import requests
import os

# spilt the environment variable and strip it to just the api key
key, value = os.environ.get('API_KEY').split(':')
api_key = value.replace('}', '').strip('"')

def get_current_weather(city="San Francisco"):
    request_url = f'https://api.openweathermap.org/data/2.5/weather?appid={api_key}&q={city}&units=imperial'
    weather_data = requests.get(request_url).json()
    return weather_data

if __name__ == "__main__":
    print('\n*** Get Current Weather Conditions***\n')
    city = input("\nEnter a City: ")

    # Check for empty string or only spaces
    if not bool(city.strip()):
        city = "San Francisco"
        
    weather_data = get_current_weather(city)
    pprint(weather_data)
