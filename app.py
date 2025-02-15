from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import re
from collections import defaultdict
from functools import wraps
import time
import json
from dotenv import load_dotenv
import secrets
import pytz

# Load environment variables
load_dotenv()

# Configure timezone
NZ_TZ = pytz.timezone('Pacific/Auckland')
UTC_TZ = pytz.UTC

def ensure_tz_aware(dt, default_tz=UTC_TZ):
    """Ensure a datetime is timezone aware. If naive, assume it's in default_tz."""
    if dt.tzinfo is None:
        return default_tz.localize(dt)
    return dt

def utc_to_nz(utc_dt):
    """Convert datetime to New Zealand time.
    
    Args:
        utc_dt: A datetime object, either naive (assumed UTC) or tz-aware
    Returns:
        A timezone-aware datetime in NZ time
    """
    utc_dt = ensure_tz_aware(utc_dt)
    return utc_dt.astimezone(NZ_TZ)

def nz_to_utc(nz_dt):
    """Convert NZ datetime to UTC.
    
    Args:
        nz_dt: A datetime object, either naive (assumed NZ) or tz-aware
    Returns:
        A timezone-aware datetime in UTC
    """
    nz_dt = ensure_tz_aware(nz_dt, NZ_TZ)
    return nz_dt.astimezone(UTC_TZ)

def now_nz():
    """Get current time in New Zealand."""
    return datetime.now(NZ_TZ)

def today_nz():
    """Get current date in New Zealand."""
    return now_nz().date()

def start_of_day_nz(dt=None):
    """Get start of day in NZ time for given date (defaults to today)."""
    if dt is None:
        dt = now_nz()
    dt = ensure_tz_aware(dt, NZ_TZ)
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)

def end_of_day_nz(dt=None):
    """Get end of day in NZ time for given date (defaults to today)."""
    if dt is None:
        dt = now_nz()
    dt = ensure_tz_aware(dt, NZ_TZ)
    return dt.replace(hour=23, minute=59, second=59, microsecond=999999)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///coffee_leaderboard.db')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'heic', 'heif', 'webp'}

# Production settings
if os.getenv('FLASK_ENV') == 'production':
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

@app.template_filter('capitalize_name')
def capitalize_name(name):
    """Template filter to properly capitalize a name."""
    if not name:
        return ""
    return " ".join(word[0].upper() + word[1:].lower() for word in name.split())

# Rate limiting settings
RATE_LIMIT_MINUTES = 5  # Time window for rate limit
MAX_SUBMISSIONS = 3     # Maximum submissions within the time window
submission_history = defaultdict(list)  # Track submission timestamps per IP

# Content filtering
INAPPROPRIATE_PATTERNS = [
    # Profanity patterns with variations
    r'f[u\*\@\$\#\!\^aA4]+[c\*\@\$\#\!\^kK]+',
    r'sh[i\*\@\$\#\!\^]+[t\*\@\$\#\!\^]+',
    r'b[i\*\@\$\#\!\^]+[t\*\@\$\#\!\^]+ch',
    r'a[s\*\@\$\#\!\^]+[s\*\@\$\#\!\^]*h[o\*\@\$\#\!\^]+[l\*\@\$\#\!\^]*e',
    r'd[i\*\@\$\#\!\^]+[c\*\@\$\#\!\^]+k',
    r'p[u\*\@\$\#\!\^]+[s\*\@\$\#\!\^]+[y\*\@\$\#\!\^]+',
    r'c[u\*\@\$\#\!\^]+[n\*\@\$\#\!\^]+t',
    # Racial slurs and hate speech patterns
    r'n+[i\*\@\$\#\!\^]+[g\*\@\$\#\!\^]+[g\*\@\$\#\!\^]*[e\*\@\$\#\!\^]+[r\*\@\$\#\!\^]*',
    r'f[a\*\@\$\#\!\^]+g+[o\*\@\$\#\!\^]*t*',
    r'k+[y\*\@\$\#\!\^]+k+[e\*\@\#\!\^]*',
    r'w+[e\*\@\$\#\!\^]+tb+[a\*\@\$\#\!\^]*c*k*',
    r'r+[e\*\@\$\#\!\^]+t+[a\*\@\$\#\!\^]*r*d*',
    r'ch+[i\*\@\$\#\!\^]+n+[k\*\@\$\#\!\^]*',
]

# Additional common substitutions to check
SUBSTITUTIONS = {
    'a': ['4', '@', 'α', 'а'],
    'i': ['1', '!', '|', 'і', 'ι'],
    'e': ['3', '€', 'е', 'ε'],
    'o': ['0', 'о', 'ο'],
    's': ['5', '$', 'ѕ'],
    't': ['7', '+', 'т'],
    'k': ['к'],
    'u': ['υ', 'ц'],
    'n': ['η', 'п'],
    'r': ['я'],
    'x': ['×'],
    'y': ['ү', 'у'],
}

def normalize_text(text):
    """Normalize text by replacing common substitution characters."""
    text = text.lower()
    for char, substitutions in SUBSTITUTIONS.items():
        for sub in substitutions:
            text = text.replace(sub, char)
    return text

def is_inappropriate(text):
    """Check if text contains inappropriate content."""
    # Normalize the text first
    normalized_text = normalize_text(text)
    
    # Check against patterns
    if any(re.search(pattern, normalized_text) for pattern in INAPPROPRIATE_PATTERNS):
        return True
        
    # Additional checks for common variations and concatenations
    words = normalized_text.split()
    joined_text = ''.join(words)  # Check for words joined together
    if any(re.search(pattern, joined_text) for pattern in INAPPROPRIATE_PATTERNS):
        return True
        
    return False

def check_rate_limit():
    """Check if the current IP has exceeded the rate limit."""
    ip = request.remote_addr
    now = now_nz()
    # Clean up old entries
    submission_history[ip] = [ts for ts in submission_history[ip] 
                            if now - ts < timedelta(minutes=RATE_LIMIT_MINUTES)]
    # Check if limit exceeded
    return len(submission_history[ip]) >= MAX_SUBMISSIONS

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if check_rate_limit():
            flash(f'Please wait {RATE_LIMIT_MINUTES} minutes between submissions.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class CoffeeEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    coffee_count = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    photos = db.relationship('CoffeePhoto', backref='entry', lazy=True, order_by='CoffeePhoto.timestamp.desc()')
    unlocked_achievements = db.relationship('UnlockedAchievement', backref='user', lazy=True)

    @property
    def created_at_nz(self):
        """Get created_at in New Zealand time."""
        return utc_to_nz(self.created_at)

    @property
    def created_date_nz(self):
        """Get created date in New Zealand time."""
        return self.created_at_nz.date()

class CoffeePhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    entry_id = db.Column(db.Integer, db.ForeignKey('coffee_entry.id'), nullable=False)
    photo_path = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def timestamp_nz(self):
        """Get timestamp in New Zealand time."""
        return utc_to_nz(self.timestamp)

class UnlockedAchievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('coffee_entry.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    emoji = db.Column(db.String(10))
    unlocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    achievement_type = db.Column(db.String(50))  # e.g., 'streak', 'volume', 'consistency'

class FeaturedPhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    photo_id = db.Column(db.Integer, db.ForeignKey('coffee_photo.id'), nullable=False)
    feature_type = db.Column(db.String(20), nullable=False)  # 'week' or 'month'
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    selected_by = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    photo = db.relationship('CoffeePhoto', backref='featured_as', lazy=True)
    admin = db.relationship('Admin', backref='featured_selections', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    leaderboard = CoffeeEntry.query.order_by(CoffeeEntry.coffee_count.desc()).limit(10).all()
    
    # Get current featured photos
    current_time = now_nz()
    featured_week = FeaturedPhoto.query.filter(
        FeaturedPhoto.feature_type == 'week',
        FeaturedPhoto.start_date <= current_time,
        FeaturedPhoto.end_date > current_time
    ).first()
    
    featured_month = FeaturedPhoto.query.filter(
        FeaturedPhoto.feature_type == 'month',
        FeaturedPhoto.start_date <= current_time,
        FeaturedPhoto.end_date > current_time
    ).first()
    
    # Get most recent photo
    most_recent_photo = CoffeePhoto.query.order_by(CoffeePhoto.timestamp.desc()).first()
    
    return render_template('index.html', 
                         leaderboard=leaderboard,
                         featured_week=featured_week,
                         featured_month=featured_month,
                         most_recent_photo=most_recent_photo)

def get_streak_status(current_streak):
    """Get the streak status information based on the current streak."""
    if current_streak <= 0:
        return {
            'level': 'none',
            'emoji': '🌱',
            'message': 'Start your streak by having a coffee today!'
        }
    elif current_streak >= 30:
        return {
            'level': 'legendary',
            'emoji': '🔥',
            'message': f'Incredible! {current_streak} day streak - You\'re on fire!'
        }
    elif current_streak >= 14:
        return {
            'level': 'epic',
            'emoji': '⚡',
            'message': f'Epic {current_streak} day streak - Keep it going!'
        }
    elif current_streak >= 7:
        return {
            'level': 'awesome',
            'emoji': '✨',
            'message': f'Awesome {current_streak} day streak!'
        }
    else:
        return {
            'level': 'active',
            'emoji': '☕',
            'message': f'{current_streak} day streak - You\'re building momentum!'
        }

def get_user_stats(user):
    """Calculate various statistics for a user's coffee consumption."""
    if not user.photos:
        return None

    # Initialize stats dictionary
    stats = {}
    
    # Get all timestamps and convert to NZ time
    timestamps = [utc_to_nz(photo.timestamp) for photo in user.photos]
    timestamps.sort()
    
    # Most recent coffee
    stats['latest_coffee'] = timestamps[-1]
    
    # First coffee (coffee journey started)
    stats['first_coffee'] = timestamps[0]
    
    # Days since first coffee (in NZ timezone)
    first_coffee_date = stats['first_coffee'].date()
    today = today_nz()
    days_since_start = (today - first_coffee_date).days
    stats['days_active'] = days_since_start + 1  # Include both start and end day
    
    # Group photos by date in NZ timezone
    daily_counts = defaultdict(int)
    day_of_week_counts = defaultdict(int)
    heatmap_data = [[0] * 24 for _ in range(7)]  # 7 days x 24 hours
    
    for ts in timestamps:
        daily_counts[ts.date().isoformat()] += 1
        day_of_week_counts[ts.strftime('%A')] += 1
        # Add to heatmap data (day of week index 0-6, hour 0-23)
        day_idx = ts.weekday()  # Monday = 0, Sunday = 6
        hour = ts.hour
        heatmap_data[day_idx][hour] += 1
    
    # Sort day of week counts to maintain consistent order
    days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    sorted_day_counts = {day: day_of_week_counts.get(day, 0) for day in days_order}
    
    # Add the daily, weekly, and heatmap counts to stats
    stats['daily_counts'] = dict(daily_counts)
    stats['day_of_week_counts'] = sorted_day_counts
    stats['heatmap_data'] = heatmap_data
    
    # Average coffees per day (over active days)
    total_days_with_coffee = len(daily_counts)
    stats['avg_per_day'] = round(len(timestamps) / max(1, days_since_start + 1), 2)  # Avoid division by zero
    stats['days_with_coffee'] = total_days_with_coffee
    stats['coffee_day_ratio'] = round(total_days_with_coffee / max(1, days_since_start + 1) * 100, 1)
    
    if daily_counts:
        # Most coffees in one day
        max_day = max(daily_counts.items(), key=lambda x: x[1])
        stats['most_in_day'] = {
            'count': max_day[1],
            'date': datetime.strptime(max_day[0], '%Y-%m-%d').date()
        }
        
        # Find longest streak
        dates = sorted(datetime.strptime(d, '%Y-%m-%d').date() for d in daily_counts.keys())
        current_streak = max_streak = 1
        streak_end = dates[0]
        
        for i in range(1, len(dates)):
            if (dates[i] - dates[i-1]).days == 1:
                current_streak += 1
                if current_streak > max_streak:
                    max_streak = current_streak
                    streak_end = dates[i]
            else:
                current_streak = 1
        
        stats['longest_streak'] = {
            'days': max_streak,
            'end_date': streak_end
        }
        
        # Calculate current streak
        today = now_nz().date()
        yesterday = today - timedelta(days=1)
        current_streak = 0
        
        # Check if user had coffee today or yesterday to maintain streak
        has_today = today.isoformat() in daily_counts
        has_yesterday = yesterday.isoformat() in daily_counts
        
        if has_today or has_yesterday:
            # Start counting from yesterday if no coffee today yet
            start_date = today if has_today else yesterday
            current_streak = 1
            
            # Count backwards from the start date
            check_date = start_date - timedelta(days=1)
            while check_date.isoformat() in daily_counts:
                current_streak += 1
                check_date -= timedelta(days=1)
        
        stats['current_streak'] = current_streak
        stats['streak_status'] = get_streak_status(current_streak)
        stats['has_coffee_today'] = has_today
        
        # Busiest day of week
        busiest_day = max(sorted_day_counts.items(), key=lambda x: x[1])
        stats['busiest_day'] = {
            'day': busiest_day[0],
            'count': busiest_day[1]
        }
    
    return stats

def get_user_badge_info(user, stats):
    """Calculate badge level and special achievements for a user."""
    if not user or not stats:
        return None
        
    # Start with default badge info
    badge_info = {
        'level': 1,
        'title': 'Coffee Novice',
        'description': 'Taking the first sips of their coffee journey!',
        'color_scheme': 'bronze',
        'emoji': '🌱',
        'achievements': [],
        'streak_info': stats.get('streak_status', {
            'level': 'none',
            'emoji': '🌱',
            'message': 'Start your streak by having a coffee today!'
        })
    }

    # Calculate level based on coffee count
    if user.coffee_count >= 1000:
        badge_info.update({
            'level': 10,
            'title': 'Coffee Deity',
            'description': 'A legendary figure whose coffee prowess transcends mortal understanding!',
            'color_scheme': 'rainbow',
            'emoji': '⚡'
        })
    elif user.coffee_count >= 500:
        badge_info.update({
            'level': 9,
            'title': 'Coffee Legend',
            'description': 'Their name echoes through the halls of coffee history!',
            'color_scheme': 'mythic',
            'emoji': '🌟'
        })
    elif user.coffee_count >= 250:
        badge_info.update({
            'level': 8,
            'title': 'Coffee Archmaster',
            'description': 'Has unlocked the deepest secrets of coffee mastery!',
            'color_scheme': 'crystal',
            'emoji': '🔮'
        })
    elif user.coffee_count >= 100:
        badge_info.update({
            'level': 7,
            'title': 'Coffee Grandmaster',
            'description': 'A true coffee connoisseur whose expertise knows no bounds!',
            'color_scheme': 'gold',
            'emoji': '👑'
        })
    elif user.coffee_count >= 75:
        badge_info.update({
            'level': 6,
            'title': 'Coffee Sage',
            'description': 'Has achieved coffee enlightenment through dedication!',
            'color_scheme': 'silver',
            'emoji': '🎯'
        })
    elif user.coffee_count >= 50:
        badge_info.update({
            'level': 5,
            'title': 'Coffee Virtuoso',
            'description': 'A master of the coffee arts!',
            'color_scheme': 'emerald',
            'emoji': '💫'
        })
    elif user.coffee_count >= 30:
        badge_info.update({
            'level': 4,
            'title': 'Coffee Master',
            'description': 'Well-versed in the ways of coffee!',
            'color_scheme': 'sapphire',
            'emoji': '⭐'
        })
    elif user.coffee_count >= 20:
        badge_info.update({
            'level': 3,
            'title': 'Coffee Pro',
            'description': 'Rapidly ascending the coffee ranks!',
            'color_scheme': 'ruby',
            'emoji': '🏆'
        })
    elif user.coffee_count >= 10:
        badge_info.update({
            'level': 2,
            'title': 'Coffee Enthusiast',
            'description': 'Developing a true passion for coffee!',
            'color_scheme': 'copper',
            'emoji': '☕'
        })

    # Add achievements based on coffee stats
    achievements = []
    
    # Streak achievements
    if stats.get('current_streak', 0) >= 30:
        achievements.append({
            'title': 'Monthly Milestone',
            'description': '30 consecutive days of coffee dedication!',
            'emoji': '📅',
            'type': 'streak'
        })
    elif stats.get('current_streak', 0) >= 14:
        achievements.append({
            'title': 'Two Week Warrior',
            'description': '14 consecutive days of coffee commitment!',
            'emoji': '🔥',
            'type': 'streak'
        })
    elif stats.get('current_streak', 0) >= 7:
        achievements.append({
            'title': 'Week Champion',
            'description': 'A full week of daily coffee!',
            'emoji': '🌅',
            'type': 'streak'
        })

    # Volume achievements
    if user.coffee_count >= 1000:
        achievements.append({
            'title': 'Coffee Legend',
            'description': 'Reached the legendary 1000 coffee milestone!',
            'emoji': '👑',
            'type': 'volume'
        })
    elif user.coffee_count >= 500:
        achievements.append({
            'title': 'Coffee Elite',
            'description': 'Joined the elite 500 coffee club!',
            'emoji': '🌟',
            'type': 'volume'
        })
    elif user.coffee_count >= 100:
        achievements.append({
            'title': 'Century Club',
            'description': 'Triple digits! 100 coffees and counting!',
            'emoji': '💯',
            'type': 'volume'
        })
    elif user.coffee_count >= 50:
        achievements.append({
            'title': 'Halfway Hero',
            'description': 'Reached the impressive 50 coffee milestone!',
            'emoji': '🏆',
            'type': 'volume'
        })
    elif user.coffee_count >= 25:
        achievements.append({
            'title': 'Quarter Century',
            'description': '25 coffees logged and documented!',
            'emoji': '🌟',
            'type': 'volume'
        })
    elif user.coffee_count >= 10:
        achievements.append({
            'title': 'Double Digits',
            'description': 'Reached 10 coffees! The journey begins!',
            'emoji': '🎯',
            'type': 'volume'
        })

    # Consistency achievements
    avg_per_day = stats.get('avg_per_day', 0)
    if avg_per_day >= 3:
        achievements.append({
            'title': 'Triple Shot King',
            'description': 'Averaging 3+ coffees per day!',
            'emoji': '👑',
            'type': 'consistency'
        })
    elif avg_per_day >= 2:
        achievements.append({
            'title': 'Double Shot Pro',
            'description': 'Averaging 2+ coffees per day!',
            'emoji': '⚡',
            'type': 'consistency'
        })
    elif avg_per_day >= 1:
        achievements.append({
            'title': 'Daily Devotee',
            'description': 'Averaging at least one coffee per day!',
            'emoji': '☕',
            'type': 'consistency'
        })

    # Time-based achievements
    days_active = stats.get('days_active', 0)
    if days_active >= 365:
        achievements.append({
            'title': 'Coffee Veteran',
            'description': 'One year of coffee tracking dedication!',
            'emoji': '🎖️',
            'type': 'veteran'
        })
    elif days_active >= 180:
        achievements.append({
            'title': 'Coffee Enthusiast',
            'description': 'Six months of coffee tracking!',
            'emoji': '🏅',
            'type': 'veteran'
        })
    elif days_active >= 90:
        achievements.append({
            'title': 'Coffee Regular',
            'description': 'Three months of coffee tracking!',
            'emoji': '🎯',
            'type': 'veteran'
        })
    elif days_active >= 30:
        achievements.append({
            'title': 'Coffee Initiate',
            'description': 'One month of coffee tracking!',
            'emoji': '🌱',
            'type': 'veteran'
        })

    # Special achievements
    if stats.get('most_in_day', {}).get('count', 0) >= 5:
        achievements.append({
            'title': 'Coffee Marathon',
            'description': '5+ coffees in a single day!',
            'emoji': '🏃',
            'type': 'special'
        })

    if stats.get('longest_streak', {}).get('days', 0) >= 30:
        achievements.append({
            'title': 'Iron Will',
            'description': 'Achieved a 30+ day streak!',
            'emoji': '⚔️',
            'type': 'special'
        })

    # Add achievements to badge info
    badge_info['achievements'] = achievements
    
    return badge_info

def unlock_achievement(user, achievement):
    """Unlock an achievement for a user if they don't already have it."""
    existing = UnlockedAchievement.query.filter_by(
        user_id=user.id,
        title=achievement['title']
    ).first()
    
    if not existing:
        new_achievement = UnlockedAchievement(
            user_id=user.id,
            title=achievement['title'],
            description=achievement['description'],
            emoji=achievement['emoji'],
            achievement_type=achievement['type']
        )
        db.session.add(new_achievement)
        try:
            db.session.commit()
            # Return True to indicate a new achievement was unlocked
            return True
        except:
            db.session.rollback()
    return False

def check_and_unlock_achievements(user):
    """Check and unlock any new achievements for a user."""
    stats = get_user_stats(user)
    badge_info = get_user_badge_info(user, stats)
    
    newly_unlocked = []
    for achievement in badge_info['achievements']:
        if unlock_achievement(user, achievement):
            newly_unlocked.append(achievement)
    
    return newly_unlocked

@app.route('/user/<int:user_id>')
def user_history(user_id):
    user = CoffeeEntry.query.get_or_404(user_id)
    stats = get_user_stats(user)
    badge_info = get_user_badge_info(user, stats)
    rank = request.args.get('rank', None)
    return render_template('user_history.html', user=user, stats=stats, badge_info=badge_info, rank=rank)

@app.route('/user/<int:user_id>/card')
def user_card(user_id):
    user = CoffeeEntry.query.get_or_404(user_id)
    stats = get_user_stats(user)
    badge_info = get_user_badge_info(user, stats)
    return render_template('user_card.html', user=user, stats=stats, badge_info=badge_info)

@app.route('/user/<int:user_id>/achievements')
def user_achievements(user_id):
    user = CoffeeEntry.query.get_or_404(user_id)
    stats = get_user_stats(user)
    badge_info = get_user_badge_info(user, stats)
    
    # Group achievements by type
    achievements_by_type = defaultdict(list)
    
    # First, ensure all achievements are unlocked in the database
    for achievement in badge_info['achievements']:
        unlock_achievement(user, achievement)
    
    # Now get all unlocked achievements from the database
    unlocked_achievements = UnlockedAchievement.query.filter_by(user_id=user.id).all()
    for achievement in unlocked_achievements:
        achievements_by_type[achievement.achievement_type].append({
            'title': achievement.title,
            'description': achievement.description,
            'emoji': achievement.emoji,
            'type': achievement.achievement_type,
            'unlocked_at': achievement.unlocked_at
        })
    
    return render_template(
        'user_achievements.html',
        user=user,
        stats=stats,
        badge_info=badge_info,
        achievements_by_type=dict(achievements_by_type)
    )

def is_valid_name(name):
    """Check if the name is in valid first last format."""
    # Split name into parts and filter out empty strings
    parts = [part for part in name.strip().split() if part]
    
    # Check if we have exactly 2 parts (first and last name)
    if len(parts) != 2:
        if len(parts) < 2:
            return False, "Please enter both your first and last name"
        else:
            return False, "Please enter only your first and last name (no middle names)"
    
    # Check if each part is a valid name (letters and basic characters only)
    for part in parts:
        if not re.match(r'^[A-Za-z\-\']+$', part):
            return False, "Names can only contain letters, hyphens (-), and apostrophes (')"
            
    return True, None

@app.route('/submit', methods=['POST'])
@rate_limit
def submit():
    name = request.form.get('name', '').strip()
    if not name:
        flash('Please enter your name')
        return redirect(url_for('index'))

    # Content filtering with enhanced checks
    if is_inappropriate(name):
        flash('Please keep it family-friendly! Inappropriate content is not allowed. 😊')
        return redirect(url_for('index'))

    # Name format validation
    is_valid, error_message = is_valid_name(name)
    if not is_valid:
        flash(error_message)
        return redirect(url_for('index'))

    # Convert to lowercase after validation
    name = name.lower()

    photo = request.files.get('photo')
    if not photo:
        flash('Please upload a photo')
        return redirect(url_for('index'))

    # Check if the file is actually present in the request
    if photo.filename == '':
        flash('No photo selected')
        return redirect(url_for('index'))

    # Check file size (before reading the file)
    try:
        photo.seek(0, 2)  # Seek to end of file
        size = photo.tell()  # Get size
        photo.seek(0)  # Reset file pointer
        if size > app.config['MAX_CONTENT_LENGTH']:
            flash('Photo is too large. Maximum size is 50MB.')
            return redirect(url_for('index'))
    except Exception as e:
        flash('Error checking file size. Please try again.')
        return redirect(url_for('index'))

    # Check file type
    if not allowed_file(photo.filename):
        flash(f'Invalid file type. Please upload a photo in one of these formats: {", ".join(ALLOWED_EXTENSIONS)}')
        return redirect(url_for('index'))

    try:
        # Record the submission time for rate limiting
        ip = request.remote_addr
        submission_history[ip].append(now_nz())

        filename = secure_filename(photo.filename)
        timestamp = now_nz().strftime('%Y%m%d_%H%M%S_')
        filename = timestamp + filename
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        photo_path = os.path.join('uploads', filename)
        photo.save(os.path.join('static', photo_path))

        existing_entry = CoffeeEntry.query.filter_by(name=name).first()
        old_coffee_count = 0
        if existing_entry:
            old_coffee_count = existing_entry.coffee_count
            existing_entry.coffee_count += 1
            new_photo = CoffeePhoto(entry_id=existing_entry.id, photo_path=photo_path)
            db.session.add(new_photo)
            user = existing_entry
        else:
            new_entry = CoffeeEntry(name=name)
            db.session.add(new_entry)
            db.session.flush()  # This ensures we get the id of the new entry
            new_photo = CoffeePhoto(entry_id=new_entry.id, photo_path=photo_path)
            db.session.add(new_photo)
            user = new_entry

        db.session.commit()

        # Check for level up
        level_up = check_level_up(user, old_coffee_count)
        if level_up:
            session['level_up'] = level_up

        # Check for new achievements
        newly_unlocked = check_and_unlock_achievements(user)
        if newly_unlocked:
            achievement_names = [a['title'] for a in newly_unlocked]
            flash(f'New achievement{"s" if len(newly_unlocked) > 1 else ""} unlocked: {", ".join(achievement_names)}!')

        flash('Coffee added successfully! ☕')
    except Exception as e:
        flash('Error uploading photo. Please try again.')
        return redirect(url_for('index'))
    
    return redirect(url_for('index'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()

        if admin and admin.check_password(password):
            login_user(admin)
            return redirect(url_for('admin'))
        
        flash('Invalid username or password')
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    entries = CoffeeEntry.query.all()
    photos = CoffeePhoto.query.order_by(CoffeePhoto.timestamp.desc()).limit(50).all()
    return render_template('admin.html', entries=entries, photos=photos)

@app.route('/admin/delete_photo/<int:photo_id>')
@login_required
def delete_photo(photo_id):
    photo = CoffeePhoto.query.get_or_404(photo_id)
    entry = CoffeeEntry.query.get(photo.entry_id)
    if entry.coffee_count > 0:
        entry.coffee_count -= 1
    
    # Delete the actual file
    file_path = os.path.join('static', photo.photo_path)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    db.session.delete(photo)
    db.session.commit()
    flash('Photo deleted successfully')
    return redirect(url_for('admin'))

@app.route('/admin/delete_entry/<int:entry_id>')
@login_required
def delete_entry(entry_id):
    entry = CoffeeEntry.query.get_or_404(entry_id)
    
    # First delete all unlocked achievements
    UnlockedAchievement.query.filter_by(user_id=entry.id).delete()
    
    # Delete all associated photos and their files
    for photo in entry.photos:
        file_path = os.path.join('static', photo.photo_path)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    # Delete all photos from database
    CoffeePhoto.query.filter_by(entry_id=entry.id).delete()
    
    # Finally delete the entry itself
    db.session.delete(entry)
    
    try:
        db.session.commit()
        flash('Entry and all associated data deleted successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting entry: ' + str(e))
    
    return redirect(url_for('admin'))

@app.route('/admin/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required')
        return redirect(url_for('admin'))
    
    admin = Admin.query.get(current_user.id)
    if not admin.check_password(current_password):
        flash('Current password is incorrect')
        return redirect(url_for('admin'))
    
    if new_password != confirm_password:
        flash('New passwords do not match')
        return redirect(url_for('admin'))
    
    if len(new_password) < 8:
        flash('New password must be at least 8 characters long')
        return redirect(url_for('admin'))
    
    admin.set_password(new_password)
    db.session.commit()
    flash('Password changed successfully')
    return redirect(url_for('admin'))

@app.route('/admin/update_user/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    try:
        user = CoffeeEntry.query.get_or_404(user_id)
        
        # Update other custom fields
        user.favorite_time = request.form.get('favorite_time', '').strip() or None
        user.coffee_variety = int(request.form.get('coffee_variety', 1))
        user.perfect_timing = int(request.form.get('perfect_timing', 0))
        user.coffee_master_points = int(request.form.get('coffee_master_points', 0))
        
        db.session.commit()
        return jsonify({'message': 'User settings updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error updating user: {str(e)}'}), 500

@app.route('/admin/reset_user/<int:user_id>', methods=['POST'])
@login_required
def reset_user(user_id):
    user = CoffeeEntry.query.get_or_404(user_id)
    user.favorite_time = None
    user.coffee_variety = 1
    user.perfect_timing = 0
    user.coffee_master_points = 0
    db.session.commit()
    return jsonify({'message': 'User customizations reset successfully'})

@app.route('/admin/get_user/<int:user_id>')
@login_required
def get_user(user_id):
    user = CoffeeEntry.query.get_or_404(user_id)
    return jsonify({
        'favorite_time': user.favorite_time,
        'coffee_variety': user.coffee_variety,
        'perfect_timing': user.perfect_timing,
        'coffee_master_points': user.coffee_master_points
    })

def check_level_up(user, old_coffee_count):
    """Check if user has leveled up and return level up info if they did."""
    old_level = 1
    if old_coffee_count >= 1000:
        old_level = 10
    elif old_coffee_count >= 500:
        old_level = 9
    elif old_coffee_count >= 250:
        old_level = 8
    elif old_coffee_count >= 100:
        old_level = 7
    elif old_coffee_count >= 75:
        old_level = 6
    elif old_coffee_count >= 50:
        old_level = 5
    elif old_coffee_count >= 30:
        old_level = 4
    elif old_coffee_count >= 20:
        old_level = 3
    elif old_coffee_count >= 10:
        old_level = 2

    new_level = 1
    if user.coffee_count >= 1000:
        new_level = 10
    elif user.coffee_count >= 500:
        new_level = 9
    elif user.coffee_count >= 250:
        new_level = 8
    elif user.coffee_count >= 100:
        new_level = 7
    elif user.coffee_count >= 75:
        new_level = 6
    elif user.coffee_count >= 50:
        new_level = 5
    elif user.coffee_count >= 30:
        new_level = 4
    elif user.coffee_count >= 20:
        new_level = 3
    elif user.coffee_count >= 10:
        new_level = 2

    if new_level > old_level:
        stats = get_user_stats(user)
        badge_info = get_user_badge_info(user, stats)
        return {
            'old_level': old_level,
            'new_level': new_level,
            'title': badge_info['title'],
            'description': badge_info['description'],
            'emoji': badge_info['emoji'],
            'color_scheme': badge_info['color_scheme']
        }
    return None

@app.route('/increment/<int:user_id>', methods=['POST'])
def increment_coffee(user_id):
    user = CoffeeEntry.query.get_or_404(user_id)
    old_count = user.coffee_count
    user.coffee_count += 1
    
    # Check for level up
    level_up = check_level_up(user, old_count)
    if level_up:
        session['level_up'] = level_up
    
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/clear_level_up', methods=['POST'])
def clear_level_up():
    if 'level_up' in session:
        session.pop('level_up')
    return '', 204

@app.route('/search_user', methods=['POST'])
def search_user():
    name = request.form.get('search_name', '').strip().lower()
    if not name:
        flash('Please enter your name')
        return redirect(url_for('index'))
    
    # Find the user
    user = CoffeeEntry.query.filter_by(name=name).first()
    if not user:
        flash('No user found with that name')
        return redirect(url_for('index'))
    
    # Get user's rank
    rank_query = db.session.query(
        CoffeeEntry,
        db.func.row_number().over(
            order_by=CoffeeEntry.coffee_count.desc()
        ).label('rank')
    ).subquery()
    
    user_rank = db.session.query(rank_query.c.rank).filter(
        rank_query.c.id == user.id
    ).scalar()
    
    return redirect(url_for('user_history', user_id=user.id, rank=user_rank))

@app.route('/admin/feature_photo', methods=['POST'])
@login_required
def feature_photo():
    photo_id = request.form.get('photo_id')
    feature_type = request.form.get('feature_type')  # 'week' or 'month'
    
    if not photo_id or not feature_type or feature_type not in ['week', 'month']:
        flash('Invalid request parameters')
        return redirect(url_for('admin'))
        
    photo = CoffeePhoto.query.get_or_404(photo_id)
    
    # Calculate start and end dates based on feature type
    start_date = start_of_day_nz()
    if feature_type == 'week':
        end_date = start_date + timedelta(days=7)
    else:  # month
        # Get the first day of next month
        next_month = start_date.replace(day=28) + timedelta(days=4)
        end_date = next_month - timedelta(days=next_month.day)
    
    # Remove any existing featured photos of the same type that overlap
    existing_features = FeaturedPhoto.query.filter(
        FeaturedPhoto.feature_type == feature_type,
        FeaturedPhoto.end_date > start_date
    ).all()
    for feature in existing_features:
        db.session.delete(feature)
    
    # Create new featured photo
    featured = FeaturedPhoto(
        photo_id=photo_id,
        feature_type=feature_type,
        start_date=start_date,
        end_date=end_date,
        selected_by=current_user.id
    )
    
    db.session.add(featured)
    db.session.commit()
    
    flash(f'Photo has been set as photo of the {feature_type}!')
    return redirect(url_for('admin'))

@app.route('/admin/unfeature_photo/<int:feature_id>', methods=['POST'])
@login_required
def unfeature_photo(feature_id):
    feature = FeaturedPhoto.query.get_or_404(feature_id)
    db.session.delete(feature)
    db.session.commit()
    
    flash('Featured photo has been removed')
    return redirect(url_for('admin'))

# Make timezone available in templates
@app.context_processor
def inject_timezone():
    return {'NZ_TZ': NZ_TZ}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin user if none exists
        if not Admin.query.first():
            admin = Admin(username=os.getenv('ADMIN_USERNAME', 'admin'))
            admin.set_password(os.getenv('ADMIN_PASSWORD', 'admin123'))
            db.session.add(admin)
            db.session.commit()
    
    if os.getenv('FLASK_ENV') == 'production':
        app.run(host='127.0.0.1', port=int(os.getenv('PORT', 8000)))
    else:
        app.run(debug=True) 